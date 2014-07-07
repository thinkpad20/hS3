{-# LANGUAGE ViewPatterns, OverloadedStrings #-}
-----------------------------------------------------------------------------
-- |
-- Module      :  Network.AWS.Authentication
-- Copyright   :  (c) Greg Heartsfield 2007
-- License     :  BSD3
--
-- Implements authentication and low-level communication with Amazon
-- Web Services, such as S3, EC2, and others.
-- API Version 2006-03-01
-- <http://docs.amazonwebservices.com/AmazonS3/2006-03-01/>
-----------------------------------------------------------------------------

module Network.AWS.Authentication (
   -- * Function Types
   runAction, isAmzHeader, preSignedURI,
   -- * Data Types
   S3Action(..),
   -- * Misc functions
   mimeEncodeQP, mimeDecode
   ) where

import Network.AWS.AWSResult
import Network.AWS.AWSConnection
import Network.AWS.ArrowUtils
import Network.HTTP as HTTP hiding (simpleHTTP_)
import Network.HTTP.HandleStream (simpleHTTP_)
import Network.Stream (Result)
import Network.URI as URI
import qualified Data.ByteString.Lazy.Char8 as L

import Data.ByteString.Char8 (pack, unpack)

import Data.HMAC (hmac_sha1)
import qualified Codec.Binary.Base64 as B64
import Codec.Utils (Octet)

import Data.Char (intToDigit, digitToInt, ord, chr, toLower)
import Data.Bits ((.&.))
import qualified Codec.Binary.UTF8.String as US

import Data.List (sortBy, groupBy, intersperse, isInfixOf)
import Data.Maybe
import Data.Monoid
import Data.Text (Text)
import qualified Data.Text as T

import System.Time
import System.Locale

import Text.Regex

import Control.Arrow
import Control.Arrow.ArrowTree
import Text.XML.HXT.Arrow.XmlArrow
import Text.XML.HXT.Arrow.XmlOptions
import Text.XML.HXT.DOM.XmlKeywords
import Text.XML.HXT.Arrow.XmlState
import Text.XML.HXT.Arrow.ReadDocument

-- | An action to be performed using S3.
data S3Action = S3Action 
  { s3conn :: AWSConnection -- | Connection and authentication information
  , s3bucket :: Text -- | Name of bucket to act on (URL encoded)
  , s3object :: Text -- | Name of object to act on (URL encoded)
  , s3query :: Text  -- | Query parameters (requires a prefix of @?@)
  , s3metadata :: [(Text, Text)] -- | Additional header fields to send
  , s3body :: L.ByteString -- | Body of action, if sending data
  , s3operation :: RequestMethod -- | Type of action, 'PUT', 'GET', etc.
  } deriving (Show)

type ByteRequest = HTTP.HTTPRequest L.ByteString
type ByteResponse = HTTPResponse L.ByteString

-- | Transform an 'S3Action' into an HTTP request.  Does not add
--   authentication or date information, so it is not suitable for
--   sending directly to AWS.
requestFromAction :: S3Action 
                  -- ^ Action to transform
                  -> ByteRequest 
                  -- ^ Action represented as an HTTP Request.
requestFromAction a = Request 
  { rqURI = URI 
    { uriScheme = ""
    , uriAuthority = Nothing
    , uriPath = '/' : T.unpack (s3object a)
    , uriQuery = T.unpack $ s3query a
    , uriFragment = "" }
  , rqMethod = s3operation a
  , rqHeaders = header HdrHost (s3Hostname a) : headersFromAction a
  , rqBody = s3body a }

-- | A convenience function to unpack text into a string for a header.
header :: HeaderName -> Text -> Header
header hname = Header hname . T.unpack

-- | Create 'Header' objects from an action.
headersFromAction :: S3Action -> [Header]
headersFromAction = map' . s3metadata 
  where map' = map $ \(k, v) -> case k of
          "Content-Type" -> header HdrContentType v
          "Content-Length" -> header HdrContentLength v
          "Content-MD5" -> header HdrContentMD5 v
          _ -> header (HdrCustom $ T.unpack k) v
      

-- | Inspect HTTP body, and add a @Content-Length@ header with the
--   correct length, if it does not already exist.
addContentLengthHeader :: ByteRequest -> ByteRequest
addContentLengthHeader req = insertHeaderIfMissing HdrContentLength len req
  where len = show $ L.length (rqBody req)

-- | Add AWS authentication header to an HTTP request.
addAuthenticationHeader :: S3Action     
                        -- ^ Action with authentication data
                        -> ByteRequest 
                        -- ^ Request to transform
                        -> ByteRequest 
                        -- ^ Authenticated request
addAuthenticationHeader act req = insertHeader' HdrAuthorization authString req
  where authString = "AWS " <> awsAccessKey conn <> ":" <> signature
        signature = makeSignature conn $ stringToSign act req
        conn = s3conn act
        insertHeader' h s = insertHeader h (T.unpack s)

-- | Sign a string using the given authentication data
makeSignature :: AWSConnection -- ^ Action with authentication data
              -> Text -- ^ String to sign
              -> Text -- ^ Base-64 encoded signature
makeSignature c s = b64encode $ hmac_sha1 keyOctets msgOctets
  where keyOctets = stringToWords $ awsSecretKey c
        msgOctets = stringToWords s

-- | Generate text that will be signed and subsequently added to the
--   request.
stringToSign :: S3Action -> ByteRequest -> Text
stringToSign a r = mconcat [ canonicalizeHeaders r
                           , canonicalizeAmzHeaders r
                           , canonicalizeResource a]

-- | Extract header data needed for signing.
canonicalizeHeaders :: ByteRequest -> Text
canonicalizeHeaders r = mconcat [ httpVerb, "\n", hdrContentMd5, "\n"
                                , hdrContentType, "\n", dateOrExpiration, "\n"]
  where httpVerb = show $ rqMethod r
        hdrContentMd5 = getHeader HdrContentMD5
        hdrDate = getHeader HdrDate
        hdrContentType = getHeader HdrContentType
        getHeader h = fromMaybe "" $ findHeader h r
        dateOrExpiration = fromMaybe hdrDate $ findHeader HdrExpires r

-- | Extract @x-amz-*@ headers needed for signing.
--   find all headers with type HdrCustom that begin with amzHeader
--   lowercase key names
--   sort lexigraphically by key name
--   combine headers with same name
--   unfold multi-line headers
--   trim whitespace around the header
canonicalizeAmzHeaders :: ByteRequest -> Text
canonicalizeAmzHeaders r =
    let amzHeaders = filter isAmzHeader (rqHeaders r)
        amzHeaderKV = map headerToLCKeyValue amzHeaders
        sortedGroupedHeaders = groupHeaders (sortHeaders amzHeaderKV)
        uniqueHeaders = combineHeaders sortedGroupedHeaders
    in concatMap (\a -> a <> "\n") (map showHeader uniqueHeaders)

-- | Give the string representation of a (key,value) header pair.
--   Uses rules for authenticated headers.
showHeader :: (Text, Text) -> Text
showHeader (k,v) = k <> ":" <> removeLeadingTrailingWhitespace(fold_whitespace v)

-- | Replace CRLF followed by whitespace with a single space
fold_whitespace :: Text -> Text
fold_whitespace s = subRegex (mkRegex "\n\r( |\t)+") s " "

-- | strip leading/trailing whitespace
removeLeadingTrailingWhitespace :: Text -> Text
removeLeadingTrailingWhitespace s = subRegex (mkRegex "^\\s+") (subRegex (mkRegex "\\s+$") s "") ""

-- | Combine same-named headers.
combineHeaders :: [[(Text, Text)]] -> [(Text, Text)]
combineHeaders = map mergeSameHeaders

-- | Headers with same name should have values merged.
mergeSameHeaders :: [(Text, Text)] -> (Text, Text)
mergeSameHeaders h@(x:_) = let values = map snd h
                     in ((fst x), (concat $ intersperse "," values))

-- | Group headers with the same name.
groupHeaders :: [(Text, Text)] -> [[(Text, Text)]]
groupHeaders = groupBy (\a b -> fst a == fst b)

-- | Sort by key name.
sortHeaders :: [(Text, Text)] -> [(Text, Text)]
sortHeaders = sortBy (\a b -> fst a `compare` fst b)

-- | Make 'Header' easier to work with, and lowercase keys.
headerToLCKeyValue :: Header -> (Text, Text)
headerToLCKeyValue (Header k v) = (map toLower (show k), v)

-- | Determine if a header belongs in the StringToSign
isAmzHeader :: Header -> Bool
isAmzHeader h =
    case h of
      Header (HdrCustom k) _ -> isPrefix amzHeader k
      otherwise -> False

-- | is the first list a prefix of the second?
isPrefix :: Eq a => [a] -> [a] -> Bool
isPrefix a b = a == take (length a) b

-- | Prefix used by Amazon metadata headers
amzHeader :: Text
amzHeader = "x-amz-"

-- | Extract resource name, as required for signing.
canonicalizeResource :: S3Action -> Text
canonicalizeResource a = bucket <> uri <> subresource
    where uri = '/' : s3object a
          bucket = case (s3bucket a) of
                     b@(_:_) -> '/' : map toLower b
                     otherwise -> ""
          subresource = case (subresource_match) of
                          [] -> ""
                          x:_ -> x
          subresource_match = filter (\sr -> isInfixOf sr (s3query a))
                              ["?versioning", "?torrent", "?logging", "?acl", "?location"]

-- | Add a date string to a request.
addDateToReq :: Text        -- ^ Date string, in RFC 2616 format
             -> ByteRequest -- ^ Request to modify
             -> ByteRequest -- ^ Request with date header added
addDateToReq date req = 
  req {HTTP.rqHeaders = HTTP.Header HTTP.HdrDate date : HTTP.rqHeaders req}

-- | Add an expiration date to a request.
addExpirationToReq :: ByteRequest -> Text -> ByteRequest
addExpirationToReq r = addHeaderToReq r . HTTP.Header HTTP.HdrExpires

-- | Attach an HTTP header to a request.
addHeaderToReq :: ByteRequest -> Header -> ByteRequest
addHeaderToReq r h = r {HTTP.rqHeaders = h : HTTP.rqHeaders r}

-- | Get hostname to connect to. Needed for european buckets
s3Hostname :: S3Action -> Text
s3Hostname a = case s3bucket a of
  b@(_:_) -> b <> "." <> s3host
  otherwise -> s3host
  where s3host = awsHost (s3conn a)
        

-- | Get current time in HTTP 1.1 format (RFC 2616)
--   Numeric time zones should be used, but I'd rather not subvert the
--   intent of ctTZName, so we stick with the name format.  Otherwise,
--   we could send @+0000@ instead of @GMT@.
--   see:
--   <http://www.ietf.org/rfc/rfc2616.txt>
--   <http://www.ietf.org/rfc/rfc1123.txt>
--   <http://www.ietf.org/rfc/rfc822.txt>
httpCurrentDate :: IO Text
httpCurrentDate = format <$> getClockTime where
  format = formatCalendarTime defaultTimeLocale rfc822DateFormat . utcTime
  utcTime c = (toUTCTime c) {ctTZName = "GMT"}

-- | Convenience for dealing with HMAC-SHA1
stringToWords :: Text -> [Octet]
stringToWords = US.encode . T.unpack

-- | Construct the request specified by an S3Action, send to Amazon,
--   and return the response.  Todo: add MD5 signature.
runAction :: S3Action -> IO (AWSResult ByteResponse)
runAction a = runAction' a $ s3Hostname a

runAction' :: S3Action -> Text -> IO (AWSResult ByteResponse)
runAction' action hostname = do
  con <- openTCPConnection hostname $ awsPort (s3conn a)
  curDate <- httpCurrentDate
  let request = addAuthenticationHeader action $
                addContentLengthHeader $
                addDateToReq curDate $ requestFromAction action
  result <- simpleHTTP_ con request
  close con
  createAWSResult a result

-- | Construct a pre-signed URI, but don't act on it.  This is useful
--   for when an expiration date has been set, and the URI needs to be
--   passed on to a client.
preSignedURI :: S3Action -- ^ Action with resource
             -> Integer  -- ^ Expiration time, in seconds since
                         --   00:00:00 UTC on January 1, 1970
             -> URI      -- ^ URI of resource
preSignedURI action expiry = URI 
  { uriScheme = "http:",
  , uriAuthority = Just $ URIAuth "" srv (':' : port)
  , uriPath = mconcat ["/", s3bucket action, "/", s3object action]
  , uriQuery = mconcat [ beginQuery, accessKeyQuery, "&", expireQuery
                       , "&", sigQuery]
  , uriFragment = "" }
  where
    con = s3conn a
    srv = awsHost con
    port = show $ awsPort con
    accessKeyQuery = "AWSAccessKeyId=" <> awsAccessKey con
    beginQuery = case s3query action of "" -> "?"; x -> x <> "&"
    expireQuery = "Expires=" <> show expiry
    toSign = mconcat [ "GET\n\n\n", show expiry, "\n/", s3bucket action
                     , "/", s3object action]
    sigQuery = "Signature=" <> urlEncode (makeSignature c toSign)

b64encode :: Text -> Text
b64encode = T.pack . B64.encode . T.unpack

b64decode :: Text -> Maybe Text
b64decode = fmap T.pack . B64.decode . T.unpack

-- | Inspect a response for network errors, HTTP error codes, and
--   Amazon error messages.
--   We need the original action in case we get a 307 (temporary redirect)
createAWSResult :: S3Action -> Result ByteResponse 
                -> IO (AWSResult ByteResponse)
createAWSResult a b = either handleError handleSuccess b
  where handleError = return . Left . NetworkError
        handleSuccess s = case rspCode s of
          (2,_,_) -> return (Right s)
          -- temporary redirect
          (3,0,7) -> case findHeader HdrLocation s of
            Just loc -> runAction' a $ getHostname loc
            Nothing -> return $ Left $ 
              AWSError "Temporary Redirect" "Redirect without location header"
          -- no body, so no XML to parse
          (4,0,4) -> return (Left $ AWSError "NotFound" "404 Not Found")  
          otherwise -> do e <- parseRestErrorXML (L.unpack (rspBody s))
                                            return (Left e)
                                            
-- Get hostname part from http url.
getHostname :: Text -> Text
getHostname h = case parseURI h of
  Nothing -> ""
  Just uri -> case uriAuthority uri of Just auth -> uriRegName auth
                                       Nothing -> ""

-- | Find the errors embedded in an XML message body from Amazon.
parseRestErrorXML :: Text -> IO ReqError
parseRestErrorXML x = do 
  runX (readString [withValidate no] x >>> processRestError) >>= \case
    [] -> return $ AWSError "NoErrorInMsg" $
          "HTTP Error condition, but message body did not contain error code."
    x:_ -> return x

-- | Find children of @Error@ entity, use their @Code@ and @Message@
--   entities to create an 'AWSError'.
processRestError = deep (isElem >>> hasName "Error") >>>
                   split >>> first (text <<< atTag "Code") >>>
                   second (text <<< atTag "Message") >>>
                   unsplit (\x y -> AWSError x y)

-- | Decode a mime string, we know about quoted printable and base64 encoded
-- UTF-8. S3 may convert quoted printable to base64.
mimeDecode :: Text -> Text
mimeDecode a
  | isPrefix utf8qp a = mimeDecodeQP $ encodedPayload utf8qp a
  | isPrefix utf8b64 a = mimeDecodeB64 $ encodedPayload utf8b64 a
  | otherwise = a
  where
    utf8qp  = "=?UTF-8?Q?"
    utf8b64 = "=?UTF-8?B?"
    -- '=?UTF-8?Q?foobar?=' -> 'foobar'
    encodedPayload prefix = reverse . drop 2 . reverse . drop (length prefix)
  mimeDecodeQP = US.decodeString . go where
    go ('=':a:b:rest) = chr (16 * digitToInt a + digitToInt b) : go rest
    go (h:t) = h : go t
    go lst = lst
  mimeDecodeB64 s = case B64.decode $ T.unpack s of
    Nothing -> ""
    Just a ->  US.decode a

 -- Encode a String into quoted printable, if needed.
 -- eq: =?UTF-8?Q?=aa?=
mimeEncode :: Text -> Text
mimeEncode s = 
  if not $ any reservedChar s then s
  else "=?UTF-8?Q?" <> go (US.encodeString s) <> "?="
  go = T.pack . mconcat . map go' . T.unpack where
    go' c | not (reservedChar c) = [c]
          | otherwise = escape c
    escape (ord -> y) = [ '=', intToDigit $ (y `div` 16) .&. 0xf
                        , intToDigit $ y .&. 0xf ]

-- Returns whether character needs escaping. From space (0x20) till '~'
-- everything is fine. The rest are control chars, or high bit.
reservedChar :: Char -> Bool
reservedChar (ord -> x) = not $ x >= 0x20 && x <= 0x7e

{-# LANGUAGE OverloadedStrings #-}
-----------------------------------------------------------------------------
-- |
-- Module      :  Network.AWS.AWSConnection
-- Copyright   :  (c) Greg Heartsfield 2007
-- License     :  BSD3
--
-- Connection and authentication info for an Amazon AWS request.
-----------------------------------------------------------------------------
module Network.AWS.AWSConnection (
   -- * Constants
   defaultAmazonS3Host, defaultAmazonS3Port,
   -- * Function Types
   amazonS3Connection, amazonS3ConnectionFromEnv,
   -- * Data Types
   AWSConnection(..)
   ) where

import Control.Applicative ((<$>))
import Data.Text
import System.Environment

-- | An Amazon Web Services connection.  Everything needed to connect
--   and authenticate requests.
data AWSConnection = AWSConnection 
  { awsHost      :: Text -- ^ Service provider hostname
  , awsPort      :: Int  -- ^ Service provider port number
  , awsAccessKey :: Text -- ^ Access Key ID
  , awsSecretKey :: Text -- ^ Secret Access Key
  } deriving (Show)

-- | Hostname used for connecting to Amazon's production S3 service (@s3.amazonaws.com@).
defaultAmazonS3Host :: Text
defaultAmazonS3Host = "s3.amazonaws.com"

-- | Port number used for connecting to Amazon's production S3 service (@80@).
defaultAmazonS3Port :: Int
defaultAmazonS3Port = 80

-- | Create an AWSConnection to Amazon from credentials.  Uses the
--   production service.
amazonS3Connection :: Text -- ^ Access Key ID
                   -> Text -- ^ Secret Access Key
                   -> AWSConnection -- ^ Connection to Amazon S3
amazonS3Connection = AWSConnection defaultAmazonS3Host defaultAmazonS3Port

-- | Retrieve Access and Secret keys from environment variables
-- @AWS_ACCESS_KEY_ID@ and @AWS_SECRET_ACCESS_KEY@, respectively. Either 
-- variable being undefined or empty will result in @Nothing@.
amazonS3ConnectionFromEnv :: IO (Maybe AWSConnection)
amazonS3ConnectionFromEnv = do
  ak <- getEnvKey "AWS_ACCESS_KEY_ID"
  sk0 <- getEnvKey "AWS_ACCESS_KEY_SECRET"
  sk1 <- getEnvKey "AWS_SECRET_ACCESS_KEY"
  return $ case (ak, sk0, sk1) of
    (Nothing, _, _) -> Nothing
    ( _, Nothing, Nothing) -> Nothing
    (Just ak, Nothing, Just sk1) -> Just $ amazonS3Connection ak sk1
    (Just ak, Just sk0, _) -> Just $ amazonS3Connection ak sk0
  where getEnvKey s = fmap (fmap pack . lookup s) getEnvironment


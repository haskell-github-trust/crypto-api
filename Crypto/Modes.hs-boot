{-# LANGUAGE CPP #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 
 Authors: Thomas DuBuisson


 Generic mode implementations useable by any correct BlockCipher
 instance Be aware there are no tests for CFB mode yet.  See
 'Test.Crypto'.
-}
module Crypto.Modes where
  import {-# SOURCE #-} Crypto.Classes
  import Crypto.Types
  import Data.ByteString as B
  import Data.ByteString.Lazy as L
  dblIV   :: BlockCipher k => IV k -> IV k
  cbcMac' :: BlockCipher k => k -> B.ByteString -> B.ByteString
  cbcMac  :: BlockCipher k => k -> L.ByteString -> L.ByteString
  cMac    :: BlockCipher k => k -> L.ByteString -> L.ByteString
  cMac'   :: BlockCipher k => k -> B.ByteString -> B.ByteString
  cMacStar :: BlockCipher k => k -> [L.ByteString] -> L.ByteString
  cMacStar' :: BlockCipher k => k -> [B.ByteString] -> B.ByteString

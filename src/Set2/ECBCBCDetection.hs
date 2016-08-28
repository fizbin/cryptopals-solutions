{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}

module Set2.ECBCBCDetection where

import qualified Data.ByteString as B
import Data.Monoid
import Data.Proxy
import Data.Word
import Control.Applicative
import Control.Monad.Except
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Random
import qualified Set2.ImplementCBC as CBC
import qualified Set2.PKCS7Padding as P7

randomInt :: forall m. (MonadRandom m) => Int -> Int -> m Int
randomInt lo hi = liftM (lo +) $ from0 (1 + hi - lo)
  where
    from0 :: Int -> m Int
    from0 limit = do
      base <- getRandomBytes 4
      let toN [] = 0
          toN (x:xs) = fromIntegral x + 256 * toN xs
          base' = (toN $ B.unpack base) :: Word32
          bMod = base' `mod` fromIntegral limit
      if base' - bMod < (0 :: Word32) - fromIntegral limit
        then return (fromIntegral bMod)
        else from0 limit

randomAES :: (MonadRandom m) => m (Either String AES128)
randomAES = randomCipher

randomCipher :: forall m c. (MonadRandom m, Cipher c) => m (Either String c)
randomCipher = do
  let keySizeSpec = cipherKeySize (undefined :: c)
  keySize <- case keySizeSpec of
    KeySizeRange lo hi -> randomInt lo hi
    KeySizeEnum xs -> liftM (xs !!) $ randomInt 0 (length xs - 1)
    KeySizeFixed i -> return i
  key <- getRandomBytes keySize :: m B.ByteString
  let inited = cipherInit key
  case inited of
    CryptoPassed x -> return $ Right x
    CryptoFailed x -> return $ Left $ show x

randomEncrypt :: forall m. (MonadRandom m) => Int -> B.ByteString ->
                 m (Either String B.ByteString)
randomEncrypt n plainText' = do
  let p = Proxy :: Proxy AES128
  (if n == 0 then randomEncryptEBC else randomEncryptCBC) plainText' p
  where
    doRandomEncrypt plainText p rest = runExceptT $ do
      cipher <- (`asProxyTypeOf` p) <$> ExceptT randomCipher
      prefixLen <- lift $ randomInt 5 10
      suffixLen <- lift $ randomInt 5 10
      prefix <- lift $ getRandomBytes prefixLen
      suffix <- lift $ getRandomBytes suffixLen
      lift $ rest cipher (prefix <> plainText <> suffix)

    randomEncryptCBC :: (BlockCipher c) => B.ByteString ->
                        Proxy c -> m (Either String B.ByteString)
    randomEncryptCBC plainText cipherP =
      doRandomEncrypt plainText cipherP $ \cipher stuff -> do
        iv <- getRandomBytes (blockSize cipher)
        return $ CBC.encryptIVPad cipher iv stuff

    randomEncryptEBC :: (BlockCipher c) => B.ByteString ->
                        Proxy c -> m (Either String B.ByteString)
    randomEncryptEBC plainText cipherP =
      doRandomEncrypt plainText cipherP $ \cipher stuff ->
      return $ ecbEncrypt cipher $ P7.pad (blockSize cipher) stuff

ecbcbcDetector :: (Monad m) => (B.ByteString -> m (Either String B.ByteString))
                  -> m Int
ecbcbcDetector oracle = do
  let myBlockSize = blockSize (undefined :: AES128)
  encryptResult <- oracle $ B.replicate (3 * myBlockSize - 1) 65
  encrypted <- either fail return encryptResult
  let mkBlocks bs = if B.null bs then []
                    else let (a, b) = B.splitAt myBlockSize bs
                         in a : mkBlocks b
      blocks = mkBlocks encrypted
      hasIdentical [] = False
      hasIdentical (a:as) = a `elem` as || hasIdentical as
  return $ if hasIdentical blocks then 0 else 1

answer :: IO ()
answer = do
  drg0 <- drgNew
  let runTest n gen = do
        let (ans, gen') = withDRG gen $ ecbcbcDetector (randomEncrypt n)
        when (ans /= n)
          (putStrLn $ "Test failed for " ++ show n)
        return gen'
      randomTest gen = do
        let (b, gen') = withDRG gen $ B.head <$> getRandomBytes 1
        runTest (fromIntegral b `mod` 2) gen'
  drg1 <- foldM (const . runTest 0) drg0 [1..100::Int]
  drg2 <- foldM (const . runTest 1) drg1 [1..100::Int]
  _ <- foldM (const . randomTest) drg2 [1..100::Int]
  putStrLn "No failed messages above means everything passed."

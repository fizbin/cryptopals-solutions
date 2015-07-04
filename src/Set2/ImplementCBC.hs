module Set2.ImplementCBC where

import Crypto.Cipher.Types
import Crypto.Cipher.AES
import Crypto.Error
import Crypto.Random
import qualified Data.ByteString as B
import Data.Foldable (foldlM)
import Data.Monoid
import Set1.HexToB64
import Set1.FixedXOR

encryptIV :: (BlockCipher c) => c -> B.ByteString -> B.ByteString
             -> Either String (B.ByteString, B.ByteString)
encryptIVPad :: (BlockCipher c) =>
                c -> B.ByteString -> B.ByteString -> B.ByteString
encryptIVPadAttach :: (BlockCipher c, MonadRandom m) =>
                      c -> B.ByteString -> m B.ByteString

encryptIV cipher iv plainText = do
  (nextIV, accumBlocks) <- foldlM encryptBlock (iv, []) blocks
  return (B.concat (reverse accumBlocks), nextIV)
  where
    blockSize' = blockSize cipher
    mkBlocks b = if B.null b then []
                 else let (blk, rest) = B.splitAt blockSize' b
                      in blk : mkBlocks rest
    blocks = mkBlocks plainText
    encryptBlock (prev, accum) block =
      let toEncrypt = fixedXOR prev block
          encrypted = ecbEncrypt cipher toEncrypt
      in if B.length block /= blockSize'
         then Left $ "Last block had length " ++ show (B.length block)
         else Right (encrypted, encrypted:accum)

encryptIVPad cipher iv plainText =
  let blockSize' = blockSize cipher
      remaining = B.length plainText `mod` blockSize'
      padLength = blockSize' - remaining
      lastByte = fromIntegral padLength
  in either error fst $
     encryptIV cipher iv (B.append plainText $ B.replicate padLength lastByte)

encryptIVPadAttach cipher plainText =
  do iv <- getRandomBytes (blockSize cipher)
     return $ iv <> encryptIVPad cipher iv plainText

decryptIV :: (BlockCipher c) => c -> B.ByteString -> B.ByteString
             -> Either String B.ByteString
decryptIVPad :: (BlockCipher c) => c -> B.ByteString -> B.ByteString
                -> Either String B.ByteString
decryptIVPadAttach :: (BlockCipher c) => c -> B.ByteString
                   -> Either String B.ByteString

decryptIV cipher iv cText = do
  (_, accumBlocks) <- foldlM decryptBlock (iv, []) blocks
  return $ B.concat $ reverse accumBlocks
  where
    blockSize' = blockSize cipher
    mkBlocks b = if B.null b then []
                 else let (blk, rest) = B.splitAt blockSize' b
                      in blk : mkBlocks rest
    blocks = mkBlocks cText
    decryptBlock (prev, accum) block =
      let decrypted = ecbDecrypt cipher block
      in if B.length block /= blockSize'
         then Left $ "Last block had length " ++ show (B.length block)
         else Right (block, fixedXOR prev decrypted : accum)

decryptIVPad cipher iv cText = do
  rawDecrypted <- if B.null cText then Left "Missing pad"
                  else decryptIV cipher iv cText
  let blockSize' = blockSize cipher
      lastByte = B.last rawDecrypted
      padLength = fromIntegral lastByte
  expectedPad <- if padLength > 0 && padLength <= blockSize'
                 then Right (B.replicate padLength lastByte)
                 else Left ("Bad last byte " ++ show lastByte)
  if B.isSuffixOf expectedPad rawDecrypted
    then return (B.take (B.length rawDecrypted - padLength) rawDecrypted)
    else Left "Missing pad"

decryptIVPadAttach cipher cText =
  let (iv, cText') = B.splitAt (blockSize cipher) cText
  in decryptIVPad cipher iv cText'

doEncryptionTest :: IO ()
doEncryptionTest = do
  let key = "YELLOW SUBMARINE" :: B.ByteString
  cipher <- case cipherInit key of
    CryptoPassed x -> return (x :: AES128)
    CryptoFailed f -> fail (show f)
  let pText = B.intercalate "  " $ replicate 125 "I am a fish."
      iv = "aejnewsoutnlhewc"
      encrypted = encryptIVPad cipher iv pText
  -- print encrypted
  -- putStrLn $ "pText length: " ++ show (B.length pText)
  -- putStrLn $ "cText length: " ++ show (B.length encrypted)
  decrypted <- either fail return $ decryptIVPad cipher iv encrypted
  if decrypted /= pText then do
    putStrLn "Round-trip failed"
    putStrLn "Decrypted:"
    print decrypted
    else putStrLn "Test passed."

answer :: IO B.ByteString
answer = do
  contents <- readFile "static/10.txt"
  cText <- either fail return $ fromB64 contents
  let key = "YELLOW SUBMARINE" :: B.ByteString
  cipher <- case cipherInit key of
    CryptoPassed x -> return (x :: AES128)
    CryptoFailed f -> fail (show f)
  either fail return $ decryptIVPad cipher (B.replicate 16 0) cText

module Set4.RARWCTR where

import Crypto.Cipher.Types
import Crypto.Random
import Data.Monoid
import Set2.ECBCBCDetection (randomAES)
import qualified Set1.AESInECBMode as ECB
import qualified Set3.ImplementCTR as CTR
import qualified Data.ByteString as B
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)

-- The type of the API exposed to the attacker
-- offset -> newText -> newCipherText
type EditAPIType = Int -> ByteString -> ByteString

edit :: (BlockCipher c) => ByteString -> c -> ByteString ->
        Int -> ByteString -> ByteString
edit cText cipher nonce offset newText =
  let (nBlocks, nBytes) = offset `divMod` blockSize cipher
      (untouched, rest) = B.splitAt (nBlocks * blockSize cipher) cText
      midBlocks = if (nBytes + B.length newText) `mod` blockSize cipher == 0
                  then (nBytes + B.length newText) `div` blockSize cipher
                  else 1 + ((nBytes + B.length newText) `div` blockSize cipher)
      (mid', untouched') = B.splitAt (midBlocks * blockSize cipher) rest
      keyBlocks = take midBlocks $ drop nBlocks $ CTR.keyStream cipher nonce
      keyRope = B.concat keyBlocks
      decrypted = BA.xor keyRope mid' :: ByteString
      replaced = B.take nBytes decrypted <> newText <>
                 B.drop (nBytes + B.length newText) decrypted
      midCrypt = BA.xor keyRope replaced
  in untouched <> midCrypt <> untouched'

makePuzzle :: IO (ByteString, EditAPIType)
makePuzzle = do
  Just plainText <- ECB.answer
  cipher <- randomAES >>= either fail return
  nonce <- getRandomBytes 8
  let cText = CTR.encrypt cipher nonce plainText
  return (cText, edit cText cipher nonce)

answer :: IO ByteString
answer = do
  (encpuzz, editAPI) <- makePuzzle
  return $ BA.xor encpuzz (editAPI 0 (B.replicate (B.length encpuzz) 0))

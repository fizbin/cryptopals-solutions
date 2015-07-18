module Set3.ImplementCTR where

import Crypto.Cipher.Types
import Crypto.Cipher.AES
import Crypto.Error
import qualified Data.ByteString as B
import Data.Bits
import Data.Word (Word8, Word64)
import Set1.HexToB64
import Set1.FixedXOR

littleEndianBstr :: Int -> Integer -> B.ByteString
littleEndianBstr _ n | n < 0 = error "Only non-negative numbers to bytestrings"
littleEndianBstr byteWidth 0 = B.replicate byteWidth 0
littleEndianBstr w _ | w <= 0 = error "Counter exceeds width"
littleEndianBstr byteWidth n =
  let b = fromIntegral $ n .&. fromIntegral (maxBound :: Word8)
  in B.cons b $ littleEndianBstr (byteWidth - 1 ) (n `shiftR` 8)

keyStream :: (BlockCipher c) => c -> B.ByteString -> [B.ByteString]
keyStream cipher nonce = stream 0
  where
    counterWidth = blockSize cipher - B.length nonce
    mkBlock n = ecbEncrypt cipher (B.append nonce
                                   $ littleEndianBstr counterWidth n)
    stream n = mkBlock n : stream (n+1)

encrypt :: (BlockCipher c) =>
           c -> B.ByteString -> B.ByteString -> B.ByteString
encrypt cipher nonce text = 
  let stream = keyStream cipher nonce
      blocked = blockify text
      myBlockSize = blockSize cipher
      blockify b | B.length b <= myBlockSize = [b]
      blockify b = let (b', b'') = B.splitAt myBlockSize b
                   in b' : blockify b''
  in B.concat $ zipWith fixedXOR stream blocked

encrypt64 :: (BlockCipher c) =>
             c -> Word64 -> B.ByteString -> B.ByteString
encrypt64 cipher =
  encrypt cipher . littleEndianBstr 8 . fromIntegral

decrypt :: (BlockCipher c) =>
           c -> B.ByteString -> B.ByteString -> B.ByteString
decrypt = encrypt

answer :: IO ()
answer = do
  let cText = fromB64' $ "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzh" ++
              "PweyyMTJULu/6/kXX0KSvoOLSFQ=="
      key = "YELLOW SUBMARINE" :: B.ByteString
  cipher <- case cipherInit key of
    CryptoPassed x -> return (x :: AES128)
    CryptoFailed f -> fail (show f)
  print $ decrypt cipher "\0\0\0\0\0\0\0\0" cText

module Set4.CTRBitFlip where

import Set2.ECBCBCDetection (randomAES)
import qualified Set1.HexToB64 as H
import qualified Set3.ImplementCTR as CTR

import Crypto.Cipher.Types
import Crypto.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Monoid
import qualified Data.ByteArray as BA

breakOracles :: (B.ByteString -> B.ByteString, B.ByteString -> Bool) ->
                Either String B.ByteString
breakOracles (encrypter, checker) = do
  let target = "A;admin=true" :: B.ByteString
      bsA = "A"
      bsB = "B"
      encA = encrypter bsA
      encB = encrypter bsB
  changeSpot <- maybe (Left "Couldn't find insertion spot") Right $
                B.elemIndex (B.head $ BA.xor bsA bsB) (BA.xor encA encB)
  let aaas = BC.replicate (B.length target) 'A'
      encAAA = encrypter aaas
      targetXOR = BA.xor aaas target
      mangled = BA.xor encAAA (B.replicate changeSpot 0 <> targetXOR
                               <> B.replicate (B.length encAAA) 0)
  if checker mangled
    then return mangled
    else Left "Solution failed"

mkOracles :: (BlockCipher c) =>
             c -> B.ByteString ->
             (B.ByteString -> B.ByteString, B.ByteString -> Bool)
mkOracles cipher nonce = (encryptedProfileFor, isAdmin)
  where
    isAdmin cText =
      let x = CTR.decrypt cipher nonce cText
      in ";admin=true;" `B.isInfixOf` x

    encryptedProfileFor userdata =
      CTR.encrypt cipher nonce (profileFor userdata)

    profileFor :: B.ByteString -> B.ByteString
    profileFor userdata = BC.pack $
                          "comment1=cooking%20MCss;userdata=" <>
                          concatMap escaper (BC.unpack userdata) <>
                          ";comment2=%20like%20a%20pound%20of%20bacon"
      where
        escaper x | x `elem` ";%=" = "%" <> H.toHex (BC.singleton x)
        escaper x = [x]

answer :: IO ()
answer = do
  cipherAttempt <- randomAES
  cipher <- either fail return cipherAttempt
  nonce <- getRandomBytes 8
  let oracles = mkOracles cipher nonce
      broken = breakOracles oracles
  case broken of
    Left err -> fail err
    Right blob -> do
      putStrLn "Success"
      putStrLn $ "Blob: " ++ show blob
      putStrLn $ "Decodes as: " ++ show (CTR.decrypt cipher nonce blob)

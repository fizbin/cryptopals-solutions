module Set3.CBCPadding where

import Control.Applicative
import Control.Arrow
import Control.Monad
import Crypto.Cipher.Types
import Crypto.Random
import Data.Bits
import qualified Data.ByteString as B
import Data.Monoid
import qualified Set2.ImplementCBC as CBC
import qualified Set1.HexToB64 as H
import Set1.FixedXOR
import qualified Set2.ECBCBCDetection as Detect
import qualified Set2.PKCS7Padding as P7
import Debug.Trace

plainTexts :: [B.ByteString]
plainTexts = map H.fromB64' [
  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
  , "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
  , "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
  , "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
  , "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
  , "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
  , "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
  , "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
  , "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
  , "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
  ]

mkOracles :: (MonadRandom m, BlockCipher c) =>
             c -> m (B.ByteString, B.ByteString -> Bool)
mkOracles cipher = do
  ptIndx <- Detect.randomInt 0 (length plainTexts - 1)
  cTxt <- CBC.encryptIVPadAttach cipher (plainTexts !! ptIndx)
  let realOracle = either (const False) (const True) .CBC.decryptIVPadAttach cipher
      traceOracle b = let (iv, rest) = B.splitAt (blockSize cipher) b
                          ans = realOracle b
                          decrypted = CBC.decryptIV cipher iv rest
                      in trace ("Decrypted was " ++ show decrypted) ans
  return (cTxt, traceOracle `seq` realOracle)

decipherText :: B.ByteString -> (B.ByteString -> Bool) ->
                Either String B.ByteString
decipherText cTxt paddingOracle' =
  --traceM $ "Block Length: " ++ show blockLength
  let blocks = mkBlocks cTxt
  in mconcat <$> zipWithM decodeBlock blocks (tail blocks)
  where
    paddingOracle = {- trace ("Asking about " ++ show b) $ -} paddingOracle'
    blockLength = (`div` 2) $ head $ filter
                  (\n -> paddingOracle $ B.reverse $ B.take n $ B.reverse cTxt)
                  [1..]
    mkBlocks bs = if B.null bs then []
                  else let (a, b) = B.splitAt blockLength bs
                       in a : mkBlocks b
    offsetXor off short = fixedXOR (B.replicate off 0 <> short)
    decodeBlock iv block = (B.singleton <$> lastByte) >>= go
      where
        checkXOR chk = paddingOracle (offsetXor (blockLength - B.length chk)
                                      chk iv <> block)
        lastByteCandidates = map (1 `xor`) $
                             filter (checkXOR . B.singleton) [minBound..maxBound]
        lastByte = case lastByteCandidates of
          [x] -> Right x
          [x1, x2] -> case (checkXOR $ "\xFF" <> B.singleton (1 `xor` x1),
                            checkXOR $ "\xFF" <> B.singleton (1 `xor` x2)) of
                        (True, False) -> Right x1
                        (False, True) -> Right x2
                        q -> Left $ "Checking two candidates yielded " ++ show q
          q -> Left $ "Last byte candidates were " ++ show q
        go bs = if B.length bs == blockLength then Right bs else
          let targetLength = 1 + B.length bs
              targetPad = B.replicate targetLength $ fromIntegral targetLength
              targetBS = fixedXOR bs targetPad
              candidates = map (fromIntegral targetLength `xor`) $
                           filter (checkXOR . (<> targetBS) . B.singleton)
                           [minBound..maxBound]
          in case candidates of
            [x] -> go $ B.singleton x <> bs
            _ -> Left $ "candidates before " ++ show bs ++ " were "
                 ++ show candidates

answer :: IO ()
answer = do
  cipher <- Detect.randomAES >>= either fail return
  (str, oracle) <- mkOracles cipher
  let ans = (P7.unpad (blockSize cipher) &&& id) <$> decipherText str oracle
  case ans of
    Right (Just x, _) -> print x
    Right (Nothing, x) -> fail $ "Decoded, but padding failed: " ++ show x
    Left err -> fail $ "Decoding error: " ++ err

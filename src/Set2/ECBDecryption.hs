{-# LANGUAGE TupleSections #-}

module Set2.ECBDecryption where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.List (elemIndex)
import Data.Monoid
import Data.Proxy
import Control.Applicative
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import qualified Set2.PKCS7Padding as P7
import qualified Set2.ECBCBCDetection as Detect
import qualified Set1.HexToB64 as H
--import Debug.Trace (trace)

mkOracle :: BlockCipher c => c -> B.ByteString -> B.ByteString
mkOracle cipher yourString =
  let whisper = H.fromB64'
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                \aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                \dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                \YnkK"
  in ecbEncrypt cipher $ P7.pad (blockSize cipher) $ yourString <> whisper

detectLengths :: (B.ByteString -> B.ByteString) -> (Int, Int, Int)
detectLengths oracle = (myBlockSize, prefixLen, suffixLen)
  where
    traceit :: String -> a -> a
    traceit msg x = msg `seq` x -- trace (msg ++ show x) x
    myBlockSize = let
      findBS2 x1 x2 = let l1 = B.length (oracle $ B.replicate x1 65)
                          l2 = B.length (oracle $ B.replicate x2 65)
                      in if l1 /= l2
                         then x2 - x1
                         else findBS2 x1 (1+x2)
      findBS1 x1 =  if B.length (oracle $ B.replicate x1 65) /=
                       B.length (oracle $ B.replicate (x1+1) 65)
                    then findBS2 (x1+1) (x1+1)
                    else findBS1 (x1+1)
      in findBS1 0
    prefixLen = let
      zeroMsgLen = B.length (oracle "")
      allAText = B.replicate (zeroMsgLen + 2*myBlockSize) 65
      oracledAllAText = oracle allAText
      oracledAllABlocks = mkBlocks oracledAllAText
      allABlock = oracledAllABlocks !! (zeroMsgLen `div` myBlockSize)
      findBLim bs = if (allABlock `elemIndex` oracledAllABlocks) /=
                       (allABlock `elemIndex`
                        mkBlocks (oracle $ bs <> allAText))
                    then B.tail bs
                    else findBLim ("B" <> bs)
      bLim = traceit "bLim = " $ B.length $ findBLim ""
      in case allABlock `elemIndex` oracledAllABlocks of
        Just i -> traceit "prefixLen = " $ i * myBlockSize - bLim
        Nothing -> error "Internal error; can't happen"
    findWhisperLength x = let whispered1 = oracle x
                              x2 = x <> "A"
                              whispered2 = oracle x2
                          in if B.length whispered1 == B.length whispered2
                             then findWhisperLength x2
                             else B.length whispered1 -
                                  B.length x - 1 - prefixLen
    suffixLen = traceit "whisperLength = " $ findWhisperLength ""
    mkBlocks bs = if B.null bs then []
                  else let (a, b) = B.splitAt myBlockSize bs
                       in a : mkBlocks b

doDetection :: (B.ByteString -> B.ByteString) ->
               Either String (Int, B.ByteString)
doDetection oracle =
  (prefixLen,) <$> decodeMore ""
  where
    traceit :: String -> a -> a
    traceit msg x = msg `seq` x -- trace (msg ++ show x) x
    (myBlockSize, prefixLen, whisperLength) = detectLengths oracle
    (prefixBlocks, prefixStuffing) = traceit "(prefixB, S) = " $
      let (prefixD, prefixM) = prefixLen `divMod` myBlockSize
      in if prefixM == 0
         then (prefixD, "")
         else (1 + prefixD, B.replicate (myBlockSize - prefixM) 65)
    mkBlocks bs = if B.null bs then []
                  else let (a, b) = B.splitAt myBlockSize bs
                       in a : mkBlocks b
    decodeMore soFar | B.length soFar == whisperLength = pure soFar
    decodeMore soFar =
      let (sfBlocks, sfRem) = B.length soFar `divMod` myBlockSize
          blockStuffing = B.reverse $ B.take (myBlockSize - 1) $ B.reverse $
                          B.replicate myBlockSize 65 <> soFar
          oracledTarget = oracle $ prefixStuffing <>
                          B.replicate (myBlockSize - 1 - sfRem) 65
          mkBlocks' = drop prefixBlocks . mkBlocks
          targetBlock = mkBlocks' oracledTarget !! sfBlocks
          oracledStuffing = oracle $
                            prefixStuffing <>
                            B.concat
                            (map ((blockStuffing <>) . B.singleton)
                             [minBound..maxBound])
          nextByte = fromIntegral <$>
                     elemIndex targetBlock (mkBlocks' oracledStuffing)
      in maybe (Left $ "Failed after " ++ show soFar ++
                " with (block, pre, post) lengths of " ++
               show (myBlockSize, prefixLen, whisperLength))
               (decodeMore . (soFar <>) . B.singleton) nextByte

answer :: IO ()
answer = do
  let p = Proxy :: Proxy AES128
  cipherAttempt <- Detect.randomCipher
  cipher <- (`asProxyTypeOf` p) <$> either fail return cipherAttempt
  let oracle = mkOracle cipher
  case doDetection oracle of
    Left err -> fail err
    Right (prefLen, suffix) -> do
                               putStrLn $ "Prefix length = " ++ show prefLen
                               putStr $ "Suffix:\n" ++ BC.unpack suffix

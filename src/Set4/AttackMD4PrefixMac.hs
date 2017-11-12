{-# LANGUAGE OverloadedStrings #-}

module Set4.AttackMD4PrefixMac where

import Set4.MD4Impl
import Crypto.Random
import Control.Monad
import Data.Binary.Get
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Monoid

makeSignatureAndVerifier :: B.ByteString -> B.ByteString
  -> (B.ByteString, B.ByteString -> B.ByteString -> Bool)
makeSignatureAndVerifier key message =
  let sig = md4 (key <> message)
      verifier message' sig' = md4 (key <> message') == sig'
  in (sig, verifier)

fakeSignature :: Int -> B.ByteString -> B.ByteString
              -> (B.ByteString, B.ByteString)
fakeSignature keyLength sampleMsg sampleSig =
  let sampleMsgPP = md4_preproc (B.replicate keyLength 0 <> sampleMsg)
      goalMsg = sampleMsgPP <> ";XXX;admin=true"
      goalMsgPP = md4_preproc goalMsg
      lastGoalBlock = B.drop (B.length goalMsgPP - 64) goalMsgPP
      [a, b, c, d] = readW32s sampleSig
      readW32s = runGet (replicateM 4 getWord32le) . BL.fromStrict
      newSig = md4' (a, b, c, d) [lastGoalBlock]
  in (B.drop keyLength goalMsg, newSig)

findSpoof :: (B.ByteString -> B.ByteString -> Bool) -> B.ByteString
          -> B.ByteString -> (B.ByteString, B.ByteString)
findSpoof verifier sampleMsg sampleSig =
  case filter (uncurry verifier) $
       map (\l -> fakeSignature l sampleMsg sampleSig) [0..256] of
    x:_ -> x
    [] -> error "No answer found"

main :: IO ()
main = do
  let baseMessage = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
  keyLength <- B.head <$> getRandomBytes 1
  key <- getRandomBytes (fromIntegral keyLength)
  let (sig, verifier) = makeSignatureAndVerifier key baseMessage
      (spoofMsg, spoofSig) = findSpoof verifier baseMessage sig
  putStrLn $ "Real message is " ++ show baseMessage
  if verifier baseMessage sig
    then putStrLn "real message verified"
    else putStrLn "REJECTED"
  putStrLn $ "Spoofed message is " ++ show spoofMsg
  if verifier spoofMsg spoofSig
    then putStrLn "spoof verified"
    else putStrLn "REJECTED"


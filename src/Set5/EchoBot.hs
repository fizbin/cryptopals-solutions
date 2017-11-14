module Set5.EchoBot where

import qualified Data.ByteArray as DBA
import Data.IORef
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Set5.DiffieHellman
import Crypto.Cipher.AES (AES128)
import Crypto.Cipher.Types (Cipher(..))
import Crypto.Error (CryptoFailable(..))
import Crypto.Random
import Crypto.Hash (hash, SHA1, Digest)
import qualified Set1.HexToB64 as H
import qualified Set2.ImplementCBC as CBC

-- Solution to https://cryptopals.com/sets/5/challenges/34

type CommChannel = B.ByteString -> IO ()
type CommBot = IORef CommChannel

newEmptyBot :: IO CommBot
newEmptyBot = newIORef (const $ pure ())

botSendChannel :: CommBot -> CommChannel
botSendChannel bot msg = do
  f <- readIORef bot
  f msg

botSetBehavior :: CommBot -> (CommBot -> CommChannel) -> IO ()
botSetBehavior a f = writeIORef a (f a)

newBot :: (CommBot -> CommChannel) -> IO CommBot
newBot f = do a <- newEmptyBot
              botSetBehavior a f
              pure a

botSetBehavior' :: CommBot -> CommChannel -> IO ()
botSetBehavior' = writeIORef

integerToCipher :: Integer -> IO AES128
integerToCipher s = do
  let sHash = hash (B8.pack $ show s) :: Digest SHA1
  sHashAsKey <- DBA.copy (DBA.view sHash 0 16) (const $ pure ())
  let maybeCipher = cipherInit (sHashAsKey :: DBA.Bytes)
  case maybeCipher of
    CryptoPassed x -> pure x
    CryptoFailed x -> fail $ show x

-- Make a cipher from a DH public key part and the private details of a DHKey
makeDHCipher :: Integer -> DHKey -> IO AES128
makeDHCipher bB key = integerToCipher . unPrivate $ getSessionKey' bB key

abot :: CommChannel -> CommBot -> CommChannel
abot partner self = aStart
  where
    aStart _ = do
      key <- makeDHKey
      let msgStr = show (toInteger (dhKeyP key), toInteger (dhKeyG key),
                         toInteger (publicKey key))
      botSetBehavior' self (aSendMessage key)
      putStrLn ">>> A: sending (p, g, A)"
      partner (B8.pack msgStr)
    aSendMessage key bResp = do
      let bB = read (B8.unpack bResp)
      cipher <- makeDHCipher bB key
      msgRandom <- H.toHex <$> getRandomBytes 5
      let msg = B8.pack $ "This is the message " ++ msgRandom
      msgE <- CBC.encryptIVPadAttach cipher msg
      putStrLn $ ">>> A: sending " ++ show msg
      botSetBehavior' self (readEcho cipher)
      partner msgE
    readEcho cipher bEcho = do
      case CBC.decryptIVPadAttach cipher bEcho of
        Left failure ->
          putStrLn $ "<<< A: failed to decrypt B's message: " ++ failure
        Right s ->
          putStrLn $ "<<< A: Got message from B: " ++ show s
      botSetBehavior' self (\_ -> putStrLn "Dead Bot A got message")

bbot :: CommChannel -> CommBot -> CommChannel
bbot partner self = bStart
  where
    bStart aMessage = do
      let (p, g, aA) = read $ B8.unpack aMessage
      key <- makeDHKey' p g
      cipher <- makeDHCipher aA key
      botSetBehavior' self (bWaitMessage cipher)
      putStrLn "<<< B: sending B"
      partner $ B8.pack $ show $ toInteger (publicKey key)
    bWaitMessage cipher aMessage = do
      j <- case CBC.decryptIVPadAttach cipher aMessage of
             Left failure -> do
               putStrLn $ ">>> B: failed to decrypt A's message: " ++ failure
               pure "**ERR**"
             Right s -> do
               putStrLn $ ">>> B: Got message from A: " ++ show s
               pure s
      putStrLn "<<< B: echoing back"
      msgE <- CBC.encryptIVPadAttach cipher j
      partner msgE

mbot :: CommChannel -> CommChannel -> CommBot -> CommChannel
mbot partnerA partnerB self = mStart
  where
    mStart aMessage = do
      let (p, g, aA) = read $ B8.unpack aMessage
      putStrLn ">>> M: intercepting (p, g, A) (sending (p,g,p))"
      let msgStr = show (p, g, p)
      botSetBehavior' self (mState2 p g aA)
      partnerB $ B8.pack msgStr
    mState2 :: Integer -> Integer -> Integer -> CommChannel
    mState2 p _ _ bMessage = do
      let bB = (read $ B8.unpack bMessage) :: Integer
      botSetBehavior' self (mStateIntercept True)
      putStrLn "<<< M: intercepting B, sending p"
      partnerA $ B8.pack $ show p
    mStateIntercept sendToB message = do
      cipher <- integerToCipher 0
      let dir = if sendToB then ">>> " else "<<< "
      case CBC.decryptIVPadAttach cipher message of
        Left failure ->
          putStrLn $ dir ++ "M: failed to decrypt intercepted message: "
          ++ failure
        Right s ->
          putStrLn $ dir ++ "M: Intercepted message: " ++ show s
      botSetBehavior' self (mStateIntercept $ not sendToB)
      (if sendToB then partnerB else partnerA) message

main :: IO ()
main = do
  putStrLn "Scenario 1"
  -- A and B talking normally
  
  robotB <- newEmptyBot
  robotA <- newBot (abot (botSendChannel robotB))
  botSetBehavior robotB (bbot (botSendChannel robotA))

  -- Kick off the conversation by sending A an empty message
  botSendChannel robotA B.empty
  
  putStrLn "------"
  putStrLn "Scenario 2"
  -- M is now in the middle of A and B
  robotM <- newBot (mbot (botSendChannel robotA)
                     (botSendChannel robotB))

  botSetBehavior robotA (abot (botSendChannel robotM))
  botSetBehavior robotB (bbot (botSendChannel robotM))

  -- Kick off the conversation by sending A an empty message
  botSendChannel robotA B.empty

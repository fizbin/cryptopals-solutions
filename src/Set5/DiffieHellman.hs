{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Set5.DiffieHellman where

import "random" System.Random

modpow :: Integer -> Integer -> Integer -> Integer
modpow _ 0 _ = 1
modpow x 1 m = x `mod` m
modpow x y m = let (h, i) = y `divMod` 2
                   xh = modpow x h m
                   xh2 = xh*xh `mod` m
               in if i == 0 then xh2 else (xh2*x) `mod` m

dh_defaultP :: Integer
dh_defaultP = read "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
              \e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
              \3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
              \6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
              \24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
              \c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
              \bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
              \fffffffffffff"

dh_defaultG :: Integer
dh_defaultG = 2

newtype PublicInt = PublicInt Integer deriving (Show, Eq, Ord, Num, Real, Enum, Integral)
newtype PrivateInt = PrivateInt Integer deriving (Eq, Ord, Show)

data DHKey = DHKey { publicKey :: PublicInt, privateKey :: PrivateInt,
                     dhKeyG :: Integer, dhKeyP :: Integer }

getSessionKey :: DHKey -> DHKey -> PrivateInt
getSessionKey dhkey1 dhkey2 = case (publicKey dhkey1, privateKey dhkey2) of
  (PublicInt a, PrivateInt b) -> PrivateInt $ modpow a b (dhKeyP dhkey1)

makeDHKey :: IO DHKey
makeDHKey = do
  a <- randomRIO (10000, dh_defaultP) :: IO Integer
  let aA = modpow dh_defaultG a dh_defaultP
  return $ DHKey (PublicInt aA) (PrivateInt a) dh_defaultG dh_defaultP

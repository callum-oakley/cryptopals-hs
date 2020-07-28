{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}

import           Data.Bits             (Bits, popCount, shiftL, shiftR, testBit,
                                        xor, (.&.))
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C
import           Data.Char             (digitToInt, intToDigit, ord)
import           Data.Foldable         (foldlM)
import           Data.List             (elemIndex, maximumBy, minimumBy, nub,
                                        unfoldr)
import           Data.List.Split       (chunksOf)
import           Data.Maybe            (fromJust)
import           Data.Ord              (comparing)
import           Data.Word             (Word8)
import           OpenSSL.Cipher        (Mode (..), aesCBC, newAESCtx)
import           Test.HUnit

-- Set 1 • Challenge 1 • Convert hex to base64
--------------------------------------------------------------------------------
decodeHex :: ByteString -> ByteString
decodeHex =
  B.pack .
  map (\[x, y] -> fromIntegral $ shiftL (digitToInt x) 4 + digitToInt y) .
  chunksOf 2 . C.unpack

encodeHex :: ByteString -> ByteString
encodeHex =
  C.pack .
  map (intToDigit . fromIntegral) .
  concatMap (\w -> [shiftR (w .&. 0xf0) 4, w .&. 0x0f]) . B.unpack

base64Chars :: String
base64Chars = ['A' .. 'Z'] <> ['a' .. 'z'] <> ['0' .. '9'] <> ['+', '/']

-- Explode a word of length n in to n (Bool) bits
explodeBits :: Bits a => Int -> a -> [Bool]
explodeBits n word = map (testBit word) [n - 1,n - 2 .. 0]

-- Collapse (Bool) bits in to a word of length n
collapseBits :: (Bits a, Num a) => Int -> [Bool] -> a
collapseBits n =
  sum . map fst . filter snd . zip [2 ^ p | p <- [n - 1,n - 2 .. 0]]

decodeBase64 :: ByteString -> ByteString
decodeBase64 =
  B.pack .
  map (collapseBits 8) .
  filter ((== 8) . length) .
  chunksOf 8 .
  concatMap (\c -> explodeBits 6 . fromJust . elemIndex c $ base64Chars) .
  filter (`elem` base64Chars) . C.unpack

encodeBase64 :: ByteString -> ByteString
encodeBase64 =
  C.pack .
  pad .
  map ((base64Chars !!) . collapseBits 6) .
  chunksOf 6 . concatMap (explodeBits 8) . B.unpack
  where
    pad x
      | length x `mod` 4 == 3 = x <> "="
      | length x `mod` 4 == 2 = x <> "=="
      | otherwise = x

testBase64Padding :: Test
testBase64Padding =
  TestCase $ do
    encodeBase64 "any carnal pleasure." @?= "YW55IGNhcm5hbCBwbGVhc3VyZS4="
    encodeBase64 "any carnal pleasure" @?= "YW55IGNhcm5hbCBwbGVhc3VyZQ=="
    encodeBase64 "any carnal pleasur" @?= "YW55IGNhcm5hbCBwbGVhc3Vy"
    decodeBase64 "YW55IGNhcm5hbCBwbGVhc3Vy" @?= "any carnal pleasur"
    decodeBase64 "YW55IGNhcm5hbCBwbGVhc3VyZQ==" @?= "any carnal pleasure"
    decodeBase64 "YW55IGNhcm5hbCBwbGVhc3VyZS4=" @?= "any carnal pleasure."

challenge1 :: Test
challenge1 = TestCase $ (encodeBase64 . decodeHex $ hex) @?= base64
  where
    hex =
      "49276d206b696c6c696e6720796f757220627261696e206c" <>
      "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

-- Set 1 • Challenge 2 • Fixed XOR
--------------------------------------------------------------------------------
(.+.) :: ByteString -> ByteString -> ByteString
a .+. b = B.pack $ zipWith xor (B.unpack a) (B.unpack b)

challenge2 :: Test
challenge2 =
  TestCase $
  encodeHex
    (decodeHex "1c0111001f010100061a024b53535009181c" .+.
     decodeHex "686974207468652062756c6c277320657965") @?=
  "746865206b696420646f6e277420706c6179"

-- Set 1 • Challenge 3 • Single-byte XOR cipher
--------------------------------------------------------------------------------
-- Counting spaces is not the most sophisticated scoring method but is good
-- enough here.
countSpaces :: ByteString -> Int
countSpaces = length . filter (== (fromIntegral . ord $ ' ')) . B.unpack

breakSingleByteXOR :: ByteString -> (Word8, ByteString)
breakSingleByteXOR ciphertext =
  (key, ciphertext .+. B.pack (replicate (B.length ciphertext) key))
  where
    key =
      maximumBy
        (comparing
           (\k ->
              countSpaces $
              ciphertext .+. B.pack (replicate (B.length ciphertext) k)))
        [0 .. 255]

challenge3 :: Test
challenge3 =
  TestCase $ do
    B.pack [key] @?= "X"
    plaintext @?= "Cooking MC's like a pound of bacon"
  where
    (key, plaintext) =
      breakSingleByteXOR . decodeHex $
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

-- Set 1 • Challenge 4 • Detect single-character XOR
--------------------------------------------------------------------------------
-- Apply our break to every ciphertext and return the highest scoring.
detectSingleByteXOR :: [ByteString] -> ByteString
detectSingleByteXOR =
  maximumBy (comparing $ countSpaces . snd . breakSingleByteXOR)

challenge4 :: Test
challenge4 =
  TestCase $ do
    ciphertexts <- map decodeHex . C.lines <$> B.readFile "data/4.txt"
    let (key, plaintext) =
          breakSingleByteXOR . detectSingleByteXOR $ ciphertexts
    B.pack [key] @?= "5"
    plaintext @?= "Now that the party is jumping\n"

-- Set 1 • Challenge 5 • Implement repeating-key XOR
--------------------------------------------------------------------------------
encryptRepeatingKeyXOR :: ByteString -> ByteString -> ByteString
encryptRepeatingKeyXOR key plaintext =
  plaintext .+.
  mconcat (replicate (B.length plaintext `div` B.length key + 1) key)

challenge5 :: Test
challenge5 =
  TestCase $ encodeHex (encryptRepeatingKeyXOR key plaintext) @?= ciphertext
  where
    plaintext =
      "Burning 'em, if you ain't quick and nimble\n" <>
      "I go crazy when I hear a cymbal"
    key = "ICE"
    ciphertext =
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623" <>
      "d63343c2a26226324272765272a282b2f20430a652e2c652a" <>
      "3124333a653e2b2027630c692b20283165286326302e27282f"

-- Set 1 • Challenge 6 • Break repeating-key XOR
--------------------------------------------------------------------------------
hammingDistance :: ByteString -> ByteString -> Int
hammingDistance a b = sum . map popCount . B.unpack $ a .+. b

testHammingDistance :: Test
testHammingDistance =
  TestCase $ hammingDistance "this is a test" "wokka wokka!!!" @?= 37

blocksOf :: Int -> ByteString -> [ByteString]
blocksOf n =
  unfoldr
    (\case
       "" -> Nothing
       s -> Just $ C.splitAt n s)

windowsOf :: Int -> [a] -> [[a]]
windowsOf n =
  unfoldr
    (\xs ->
       if length xs < n
         then Nothing
         else Just (take n xs, tail xs))

mean :: (Foldable t, Fractional a) => t a -> a
mean xs = sum xs / fromIntegral (length xs)

likelyKeysize :: ByteString -> Int
likelyKeysize ciphertext =
  minimumBy
    (comparing $ \keysize ->
       mean .
       map
         (\[a, b] -> fromIntegral (hammingDistance a b) / fromIntegral keysize) .
       windowsOf 2 . blocksOf keysize $
       ciphertext)
    [2 .. 40]

breakRepeatingKeyXOR :: ByteString -> (ByteString, ByteString)
breakRepeatingKeyXOR ciphertext = (key, plaintext)
  where
    key = B.pack . map fst $ fragments
    plaintext = mconcat . C.transpose . map snd $ fragments
    fragments =
      map breakSingleByteXOR . C.transpose . blocksOf keysize $ ciphertext
    keysize = likelyKeysize ciphertext

playThatFunkyMusic :: ByteString
playThatFunkyMusic =
  C.unlines
    [ "I'm back and I'm ringin' the bell "
    , "A rockin' on the mike while the fly girls yell "
    , "In ecstasy in the back of me "
    , "Well that's my DJ Deshay cuttin' all them Z's "
    , "Hittin' hard and the girlies goin' crazy "
    , "Vanilla's on the mike, man I'm not lazy. "
    , ""
    , "I'm lettin' my drug kick in "
    , "It controls my mouth and I begin "
    , "To just let it flow, let my concepts go "
    , "My posse's to the side yellin', Go Vanilla Go! "
    , ""
    , "Smooth 'cause that's the way I will be "
    , "And if you don't give a damn, then "
    , "Why you starin' at me "
    , "So get off 'cause I control the stage "
    , "There's no dissin' allowed "
    , "I'm in my own phase "
    , "The girlies sa y they love me and that is ok "
    , "And I can dance better than any kid n' play "
    , ""
    , "Stage 2 -- Yea the one ya' wanna listen to "
    , "It's off my head so let the beat play through "
    , "So I can funk it up and make it sound good "
    , "1-2-3 Yo -- Knock on some wood "
    , "For good luck, I like my rhymes atrocious "
    , "Supercalafragilisticexpialidocious "
    , "I'm an effect and that you can bet "
    , "I can take a fly girl and make her wet. "
    , ""
    , "I'm like Samson -- Samson to Delilah "
    , "There's no denyin', You can try to hang "
    , "But you'll keep tryin' to get my style "
    , "Over and over, practice makes perfect "
    , "But not if you're a loafer. "
    , ""
    , "You'll get nowhere, no place, no time, no girls "
    , "Soon -- Oh my God, homebody, you probably eat "
    , "Spaghetti with a spoon! Come on and say it! "
    , ""
    , "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino "
    , "Intoxicating so you stagger like a wino "
    , "So punks stop trying and girl stop cryin' "
    , "Vanilla Ice is sellin' and you people are buyin' "
    , "'Cause why the freaks are jockin' like Crazy Glue "
    , "Movin' and groovin' trying to sing along "
    , "All through the ghetto groovin' this here song "
    , "Now you're amazed by the VIP posse. "
    , ""
    , "Steppin' so hard like a German Nazi "
    , "Startled by the bases hittin' ground "
    , "There's no trippin' on mine, I'm just gettin' down "
    , "Sparkamatic, I'm hangin' tight like a fanatic "
    , "You trapped me once and I thought that "
    , "You might have it "
    , "So step down and lend me your ear "
    , "'89 in my time! You, '90 is my year. "
    , ""
    , "You're weakenin' fast, YO! and I can tell it "
    , "Your body's gettin' hot, so, so I can smell it "
    , "So don't be mad and don't be sad "
    , "'Cause the lyrics belong to ICE, You can call me Dad "
    , "You're pitchin' a fit, so step back and endure "
    , "Let the witch doctor, Ice, do the dance to cure "
    , "So come up close and don't be square "
    , "You wanna battle me -- Anytime, anywhere "
    , ""
    , "You thought that I was weak, Boy, you're dead wrong "
    , "So come on, everybody and sing this song "
    , ""
    , "Say -- Play that funky music Say, go white boy, go white boy go "
    , "play that funky music Go white boy, go white boy, go "
    , "Lay down and boogie and play that funky music till you die. "
    , ""
    , "Play that funky music Come on, Come on, let me hear "
    , "Play that funky music white boy you say it, say it "
    , "Play that funky music A little louder now "
    , "Play that funky music, white boy Come on, Come on, Come on "
    , "Play that funky music "
    ]

challenge6 :: Test
challenge6 =
  TestCase $ do
    ciphertext <- decodeBase64 <$> B.readFile "data/6.txt"
    let (key, plaintext) = breakRepeatingKeyXOR ciphertext
    key @?= "Terminator X: Bring the noise"
    plaintext @?= playThatFunkyMusic

-- Set 1 • Challenge 7 • AES in ECB mode
--------------------------------------------------------------------------------
blockCipher :: Mode -> ByteString -> ByteString -> IO ByteString
blockCipher mode key block
  | B.length block /= 16 = fail "block must be 16 bytes long"
  | otherwise = do
    ctx <- newAESCtx mode key (B.pack $ replicate 16 0)
    aesCBC ctx block

encryptECB :: ByteString -> ByteString -> IO ByteString
encryptECB key = foldlM step "" . blocksOf 16 . padPKCS7 16
  where
    step ciphertext block = do
      c <- blockCipher Encrypt key block
      return $ ciphertext <> c

decryptECB :: ByteString -> ByteString -> IO ByteString
decryptECB key = fmap unpadPKCS7 . foldlM step "" . blocksOf 16
  where
    step plaintext block = do
      p <- blockCipher Decrypt key block
      return $ plaintext <> p

challenge7 :: Test
challenge7 =
  TestCase $ do
    ciphertext <- decodeBase64 <$> B.readFile "data/7.txt"
    plaintext <- decryptECB "YELLOW SUBMARINE" ciphertext
    plaintext @?= playThatFunkyMusic

-- Set 1 • Challenge 8 • Detect AES in ECB mode
--------------------------------------------------------------------------------
countRepeatingBlocks :: ByteString -> Int
countRepeatingBlocks ciphertext = length blocks - length (nub blocks)
  where
    blocks = blocksOf 16 ciphertext

detectECB :: [ByteString] -> ByteString
detectECB = maximumBy $ comparing countRepeatingBlocks

challenge8 :: Test
challenge8 =
  TestCase $ do
    ciphertexts <- map decodeHex . C.lines <$> B.readFile "data/8.txt"
    -- Not confirmed to be correct, so test is only useful to know if I
    -- accidentally change anything.
    encodeHex (detectECB ciphertexts) @?=
      "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283" <>
      "e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd283" <>
      "9475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd283" <>
      "97a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283" <>
      "d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

-- Set 2 • Challenge 9 • Implement PKCS#7 padding
--------------------------------------------------------------------------------
padPKCS7 :: Int -> ByteString -> ByteString
padPKCS7 blockSize text = text <> B.pack (replicate n $ fromIntegral n)
  where
    n = blockSize - B.length text `mod` blockSize

unpadPKCS7 :: ByteString -> ByteString
unpadPKCS7 text = B.take (B.length text - fromIntegral (B.last text)) text

challenge9 :: Test
challenge9 =
  TestCase $
  padPKCS7 20 "YELLOW SUBMARINE" @?= "YELLOW SUBMARINE\x04\x04\x04\x04"

-- Set 2 • Challenge 10 • Implement CBC mode
--------------------------------------------------------------------------------
encryptCBC :: ByteString -> ByteString -> ByteString -> IO ByteString
encryptCBC key iv = fmap fst . foldlM step ("", iv) . blocksOf 16 . padPKCS7 16
  where
    step (ciphertext, chained) block = do
      block' <- blockCipher Encrypt key (block .+. chained)
      return (ciphertext <> block', block')

decryptCBC :: ByteString -> ByteString -> ByteString -> IO ByteString
decryptCBC key iv = fmap (unpadPKCS7 . fst) . foldlM step ("", iv) . blocksOf 16
  where
    step (plaintext, chained) block = do
      block' <- blockCipher Decrypt key block
      return (plaintext <> block' .+. chained, block)

challenge10 :: Test
challenge10 =
  TestCase $ do
    ciphertext <- decodeBase64 <$> B.readFile "data/10.txt"
    plaintext <-
      decryptCBC "YELLOW SUBMARINE" (B.pack $ replicate 16 0) ciphertext
    plaintext @?= playThatFunkyMusic

--------------------------------------------------------------------------------
main :: IO ()
main = do
  _ <-
    runTestTT $
    TestList
      [ testBase64Padding
      , testHammingDistance
      , challenge1
      , challenge2
      , challenge3
      , challenge4
      , challenge5
      , challenge6
      , challenge7
      , challenge8
      , challenge9
      , challenge10
      ]
  return ()
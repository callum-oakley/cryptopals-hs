import           Data.Bits       (Bits, popCount, shiftL, shiftR, testBit, xor,
                                  (.&.))
import           Data.Char       (chr, digitToInt, intToDigit, ord)
import           Data.List       (elemIndex, maximumBy, minimumBy, transpose)
import           Data.List.Split (chunksOf)
import           Data.Maybe      (fromJust)
import           Data.Ord        (comparing)
import           Data.Word       (Word8)
import           Test.HUnit

-- Set 1 • Challenge 1 • Convert hex to base64
--------------------------------------------------------------------------------
decodeHex :: String -> [Word8]
decodeHex =
  map (\[x, y] -> fromIntegral $ shiftL (digitToInt x) 4 + digitToInt y) .
  chunksOf 2

encodeHex :: [Word8] -> String
encodeHex =
  map (intToDigit . fromIntegral) .
  concatMap (\w -> [shiftR (w .&. 0xf0) 4, w .&. 0x0f])

decodeAscii :: String -> [Word8]
decodeAscii = map $ fromIntegral . ord

encodeAscii :: [Word8] -> String
encodeAscii = map $ chr . fromIntegral

base64Chars :: String
base64Chars = ['A' .. 'Z'] <> ['a' .. 'z'] <> ['0' .. '9'] <> ['+', '/']

-- Explode a word of length n in to n (Bool) bits
explodeBits :: Bits a => Int -> a -> [Bool]
explodeBits n word = map (testBit word) [n - 1,n - 2 .. 0]

-- Collapse (Bool) bits in to a word of length n
collapseBits :: (Bits a, Num a) => Int -> [Bool] -> a
collapseBits n =
  sum . map fst . filter snd . zip [2 ^ p | p <- [n - 1,n - 2 .. 0]]

decodeBase64 :: String -> [Word8]
decodeBase64 =
  map (collapseBits 8) .
  filter ((== 8) . length) .
  chunksOf 8 .
  concatMap (\c -> explodeBits 6 . fromJust . elemIndex c $ base64Chars) .
  filter (`elem` base64Chars)

encodeBase64 :: [Word8] -> String
encodeBase64 =
  pad .
  map ((base64Chars !!) . collapseBits 6) .
  chunksOf 6 . concatMap (explodeBits 8)
  where
    pad x
      | length x `mod` 4 == 3 = x <> "="
      | length x `mod` 4 == 2 = x <> "=="
      | otherwise = x

testBase64Padding :: Test
testBase64Padding =
  TestCase $ do
    (encodeBase64 . decodeAscii $ "any carnal pleasure.") @?=
      "YW55IGNhcm5hbCBwbGVhc3VyZS4="
    (encodeBase64 . decodeAscii $ "any carnal pleasure") @?=
      "YW55IGNhcm5hbCBwbGVhc3VyZQ=="
    (encodeBase64 . decodeAscii $ "any carnal pleasur") @?=
      "YW55IGNhcm5hbCBwbGVhc3Vy"
    (encodeAscii . decodeBase64 $ "YW55IGNhcm5hbCBwbGVhc3Vy") @?=
      "any carnal pleasur"
    (encodeAscii . decodeBase64 $ "YW55IGNhcm5hbCBwbGVhc3VyZQ==") @?=
      "any carnal pleasure"
    (encodeAscii . decodeBase64 $ "YW55IGNhcm5hbCBwbGVhc3VyZS4=") @?=
      "any carnal pleasure."

challenge1 :: Test
challenge1 = TestCase $ (encodeBase64 . decodeHex $ hex) @?= base64
  where
    hex =
      "49276d206b696c6c696e6720796f757220627261696e206c" <>
      "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

-- Set 1 • Challenge 2 • Fixed XOR
--------------------------------------------------------------------------------
(.+.) :: [Word8] -> [Word8] -> [Word8]
(.+.) = zipWith xor

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
countSpaces :: [Word8] -> Int
countSpaces = length . filter (== (fromIntegral . ord $ ' '))

breakSingleByteXOR :: [Word8] -> (Word8, [Word8])
breakSingleByteXOR ciphertext = (key, ciphertext .+. repeat key)
  where
    key =
      maximumBy
        (comparing (\k -> countSpaces $ ciphertext .+. repeat k))
        [0 .. 255]

challenge3 :: Test
challenge3 =
  TestCase $ do
    encodeAscii [key] @?= "X"
    encodeAscii plaintext @?= "Cooking MC's like a pound of bacon"
  where
    (key, plaintext) =
      breakSingleByteXOR . decodeHex $
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

-- Set 1 • Challenge 4 • Detect single-character XOR
--------------------------------------------------------------------------------
-- Apply our break to every ciphertext and return the highest scoring.
detectSingleByteXOR :: [[Word8]] -> [Word8]
detectSingleByteXOR =
  maximumBy (comparing $ countSpaces . snd . breakSingleByteXOR)

challenge4 :: Test
challenge4 =
  TestCase $ do
    ciphertexts <- readFile "data/4.txt"
    let (key, plaintext) =
          breakSingleByteXOR . detectSingleByteXOR . map decodeHex . lines $
          ciphertexts
    encodeAscii [key] @?= "5"
    encodeAscii plaintext @?= "Now that the party is jumping\n"

-- Set 1 • Challenge 5 • Implement repeating-key XOR
--------------------------------------------------------------------------------
challenge5 :: Test
challenge5 = TestCase $ encodeHex (plaintext .+. cycle key) @?= ciphertext
  where
    plaintext =
      decodeAscii $
      "Burning 'em, if you ain't quick and nimble\n" <>
      "I go crazy when I hear a cymbal"
    key = decodeAscii "ICE"
    ciphertext =
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623" <>
      "d63343c2a26226324272765272a282b2f20430a652e2c652a" <>
      "3124333a653e2b2027630c692b20283165286326302e27282f"

-- Set 1 • Challenge 6 • Break repeating-key XOR
--------------------------------------------------------------------------------
hammingDistance :: [Word8] -> [Word8] -> Int
hammingDistance a b = sum . map popCount $ a .+. b

testHammingDistance :: Test
testHammingDistance =
  TestCase $
  hammingDistance (decodeAscii "this is a test") (decodeAscii "wokka wokka!!!") @?=
  37

windowsOf :: Int -> [a] -> [[a]]
windowsOf n xs
  | length xs < n = []
  | otherwise = take n xs : windowsOf n (tail xs)

mean :: (Foldable t, Fractional a) => t a -> a
mean xs = sum xs / (fromIntegral $ length xs)

likelyKeysize :: [Word8] -> Int
likelyKeysize ciphertext =
  minimumBy
    (comparing $ \keysize ->
       mean .
       map
         (\[a, b] ->
            (fromIntegral $ hammingDistance a b) / (fromIntegral keysize)) .
       windowsOf 2 . chunksOf keysize $
       ciphertext)
    [2 .. 40]

breakRepeatingKeyXOR :: [Word8] -> ([Word8], [Word8])
breakRepeatingKeyXOR ciphertext = (key, plaintext)
  where
    key = map fst fragments
    plaintext = concat . transpose . map snd $ fragments
    fragments =
      map breakSingleByteXOR . transpose . chunksOf keysize $ ciphertext
    keysize = likelyKeysize ciphertext

playThatFunkyMusic :: String
playThatFunkyMusic =
  unlines
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
    ciphertext <- readFile "data/6.txt"
    let (key, plaintext) = breakRepeatingKeyXOR . decodeBase64 $ ciphertext
    encodeAscii key @?= "Terminator X: Bring the noise"
    encodeAscii plaintext @?= playThatFunkyMusic

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
      ]
  return ()

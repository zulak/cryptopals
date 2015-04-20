;; # Crypto Challenge Set 2
;;
;; This is the first of several sets on block cipher cryptography.
;; This is bread-and-butter crypto, the kind you'll see implemented in
;; most web software that does crypto.
;;
;; Three of the challenges in this set are extremely valuable in
;; breaking real-world crypto; one allows you to decrypt messages
;; encrypted in the default mode of AES, and the other two allow you
;; to rewrite messages encrypted in the most popular modes of AES.
;;
(ns zulak.cryptopals.set2
  (:require [zulak.cryptopals.common :as common]
            [zulak.cryptopals.set1 :as set1]
            [clojure.string :as s]
            [clojure.java.io :as io]))

;; ## Challenge 9 -- Implement PKCS#7 Padding
;;
;;
;; One way we account for irregularly-sized messages is by padding,
;; creating a plaintext that is an even multiple of the blocksize. The
;; most popular padding scheme is called PKCS#7.
;;
;; Pad any block to a specific block length, by appending the number
;; of bytes of padding to the end of the block. Remember that ALL
;; padded plaintexts must include padding, therefore if a plaintext's
;; lenfth is a mutliple of the block-size, a full block of padding
;; must be appended.

(defn challenge-9 [block-size plaintext]
  (let [plaintext-bytes (common/str->bytes plaintext)]
    (common/add-pkcs7-padding block-size plaintext-bytes)))


;; ## Challenge 10 -- Implement CBC Encryption
;;
;; CBC mode is a block cipher mode that allows us to encrypt
;; irregularly-sized messages, despite the fact that a block cipher
;; natively only transforms individual blocks.
;;
;; In CBC mode, each ciphertext block is XOR'd with the the next
;; plaintext block before the next call to the cipher core.
;;
;; [wikipedia](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29)

;; This is another place where I feel like I might be able to
;; accomplish this with reduce rather than explicit recursion. I'll
;; have to think about this some more...
;;
(defn cbc-encrypt-msg [key iv plaintext]
  (loop [blocks (partition-all 16 (common/add-pkcs7-padding 16 plaintext))
         prev-block iv
         ciphertext []]
    (if-not (seq blocks)
      ciphertext
      (let [block (first blocks)
            xored-block (set1/fixed-xor block prev-block)
            encrypted-block (do (println (count xored-block)) (common/aes-ecb-encrypt xored-block key))]
        (recur (rest blocks) encrypted-block (into ciphertext encrypted-block))))))

(defn cbc-decrypt-msg [key iv ciphertext]
  (loop [blocks (partition-all 16 ciphertext)
         prev-block iv
         plaintext []]
    (if-not (seq blocks)
      plaintext
      (let [block (first blocks)
            decrypted-block (common/aes-ecb-decrypt block key)
            plaintext-block (set1/fixed-xor decrypted-block prev-block)]
        (recur (rest blocks) block (into plaintext plaintext-block))))))

(defn challenge-10 []
  (let [input (common/b64-slurp "10.txt")
        key (common/str->bytes "YELLOW SUBMARINE")
        iv (repeat 16 0)
        plaintext-bytes (common/remove-pkcs7-padding 16 (cbc-decrypt-msg key iv input))]
    (apply str (map char plaintext-bytes))))


;; ## Challenge 11 -- An ECB/CBC detection oracle
;;
;; Detect the block cipher mode the function is using each time. You
;; should end up with a piece of code that, pointed at a block box
;; that might be encrypting ECB or CBC, tells you which one is
;; happening.

;; Have the function append 5-10 bytes (count chosen randomly) before
;; the plaintext and 5-10 bytes after the plaintext.
;;
(defn- apply-random-padding [input]
  (let [prefix-length (+ 5 (rand-int 7))
        suffix-length (+ 5 (rand-int 7))]
    (-> []
     (into (repeat prefix-length 0))
     (into input)
     (into (repeat suffix-length 0)))))

;; Write a function that encrypts data under an unknown key --- that
;; is, a function that generates a random key and encrypts under it.
;;
;; Now, have the function choose to encrypt under ECB 1/2 the time,
;; and under CBC the other half (just use random IVs each time for
;; CBC). Use rand(2) to decide which to use.
;;
(defn- rand-encrypt-msg [raw-input]
  (let [mode (rand-nth [:cbc :ecb])
        key (common/get-random-key 16)
        iv (common/get-random-key 16)
        input (apply-random-padding raw-input)]
    (condp = mode
      :cbc (do (println "picked cbc")
               (cbc-encrypt-msg key iv input))
      :ecb (do (println "picked ecb")
               (common/ecb-encrypt-msg key input)))))

(defn- encryption-oracle [encryption-fn]
  (let [plaintext (repeat 256 (int \A))
        ciphertext (encryption-fn plaintext)
        block-frequencies (frequencies (partition-all 16 ciphertext))
        max-repeated-blocks (apply max (map second block-frequencies))]
    (if (> max-repeated-blocks 1) :ecb :cbc)))

(defn challenge-11 []
  (encryption-oracle rand-encrypt-msg))

;; ## Challenge 12 -- Byte-at-a-time ECB decryption (Simple)
;;
;; Create a ciphertext with the following contents: `AES-128-ECB(your-string || unknown-string, random-key)`
;;
;; Now without the random-key, recover `unknown-string` from the ciphertext.
;;
;; ### Appraoch
;;
;; The encryption scheme here is vulnerable to attack because:
;;
;; 1. We control the input, and;
;; 2. Assuming a fixed key, a plaintext input will always produce the same ciphertext output.
;;
;; By inserting an input of known length, we can push around the
;; unknown-string such that a specific byte appears in the last
;; position of a block.
;;
;; We can then encrypt all possible (256) plaintexts to create a
;; dictionary mapping a ciphertext block to the value of the byte in
;; the block's last position. We can then use this dictionary to
;; determine the value of the unknown byte moved into position by the
;; padding.
;;
;; By varying the padding and buliding up the known plaintext, we can
;; guess the secret plaintext byte-by-byte.

(defn- repeat-bytes [num-bytes]
  (vec (repeat num-bytes (int \A))))

;; We need to store the Key and IV for use across multiple
;; encryptions, so we'll stash those values in an closure and return a
;; function that uses them. `encryption-fn` implements the following
;; behaviour from the problem: `AES-128-ECB(your-string ||
;; unknown-string, random-key)`
;;
(defn- c12-new-context []
  (let [key (common/get-random-key 16)
        secret (common/b64-slurp "12.txt")]
    {:key (common/get-random-key 16)
     :secret (common/b64-slurp "12.txt")
     :encryption-fn (fn [plaintext]
                      (common/ecb-encrypt-msg key (into (vec plaintext) secret)))}))

;; First, we need to guess the length of the cipher's blocksize.
;;
;; Recall that the length of an ECB/CBC ciphertext is always a
;; multiple of the block size. We can exploit this by adding bytes to
;; the input until the output size changes.
;;
;; The block-size is the delta between the two output sizes.
;;
(defn- find-ecb-block-size [encrypt-fn]
  (let [initial (count (encrypt-fn (repeat-bytes 0)))]
    (loop [length 1]
      (let [next (count (encrypt-fn (repeat-bytes length)))]
        (if (not= initial next)
          (- next initial)
          (recur (inc length)))))))


;; Because ECB is stateless, all identical input blocks will produce
;; identical output blocks.
;;
;; Here we are creating a block containing `$BLOCK_SIZE - 1` fixed
;; values with the last value containing all possible bytes. We can
;; use this to compare against the first block of ciphertext to
;; decrypt the 1st byte of the secret. Once we know the last byte of
;; the block, we can repeat the process with `($BLOCK_SIZE - 2 ... 1)`
;; of fixed values to decode the message one byte at a time.

;; For a given byte (position), find the block in which it is
;; contained.
(defn- get-block-for-position [block-size position ciphertext]
  (let [nth-block (quot position block-size)]
    (nth (partition-all block-size ciphertext) nth-block)))

;; Given `n` bytes of discovered plaintext, construct an input to the
;; encryption function such that the `n + 1` byte is at the last
;; position within a block.
(defn- padding-for-position [block-size plaintext]
  (let [plaintext-length (count plaintext)]
    (repeat-bytes (- (dec block-size) (mod plaintext-length block-size)))))

(defn- create-attack-ciphertext [encrypt-fn block-size known-plaintext]
  (let [position (count known-plaintext)
        prefix (padding-for-position block-size known-plaintext)]
    (get-block-for-position block-size position (encrypt-fn prefix))))


(defn- create-attack-dictionary [encrypt-fn block-size known-plaintext]
  (let [position (count known-plaintext)
        prefix (into (padding-for-position block-size known-plaintext)
                     known-plaintext)
        get-interesting-block (partial get-block-for-position block-size position)]
    ;; this function is getting seriously ugly...
    (apply hash-map
           (mapcat (fn [x]
                     [(get-interesting-block
                       (encrypt-fn (conj prefix x))) x])
                   (range 256)))))

(defn- c12-get-next-byte [encrypt-fn block-size plaintext]
  (let [dict (create-attack-dictionary encrypt-fn block-size plaintext)
        key (create-attack-ciphertext encrypt-fn block-size plaintext)]
    (get dict key)))

;; So this is an interesting problem. Because of the way that pkcs#7
;; padding works, the value of the last padding digit will change as
;; our oracle function runs. This attack exploits the fact that the
;; secret portion of the message does not change, so the variable
;; padding values break it.
;;
;; Not sure what to do about this...
;;
(defn challenge-12 [encrypt-fn block-size]
  (loop [x 144
         plaintext [(c12-get-next-byte encrypt-fn block-size [])]]
    (if (nil? (last plaintext))
      plaintext
      (recur (dec x) (conj plaintext (c12-get-next-byte encrypt-fn block-size plaintext))))))


;; ## Challenge 13 -- ECB cut-and-paste

(defn- parse-kv [kvstr]
  (reduce #(assoc % (keyword (nth %2 1)) (nth %2 2)) {} (re-seq #"(\w+)=([^&]+)" kvstr)))

(defn- profile-for [email]
  (let [sanitized-email (s/replace email #"(&|=)" "")]
    (str "email=" sanitized-email "&uid=10&role=user")))

(defn- >c13 [context email]
  (common/ecb-encrypt-msg (:key context) (common/str->bytes (profile-for email))))

(defn- <c13 [context ciphertext]
  (parse-kv (common/bytes->ascii (common/ecb-decrypt-msg (:key context) ciphertext))))

;; We can exploit the fact that we know the layout of the plaintext.
;;
;; - Since the layout of fields in the plaintext is fixed, we pick an
;; email address such that the text 'admin' appears in its own padded
;; block.
;; - Then we select an email address such that the plaintext 'user'
;; occurs in its own padded block.
;; - In order to change this to 'admin', we simply swap these two
;; blocks out. Provided that there's no checksum on the message, we
;; have successfully modified the plaintext.

(defn challenge-13 []
  (let [context {:key (common/get-random-key 16)}
        encrypt-fn (partial >c13 context)
        decrypt-fn (partial <c13 context)
        required-padding 10
        ciphertext (encrypt-fn (str (apply str (repeat required-padding \B)) "admin" (apply str (repeat 11 (char 11)))))
        admin-block (second (partition 16 ciphertext))
        prefix (vec (take 32 (encrypt-fn (apply str (repeat 13 \z)))))]
    (println required-padding)
    (decrypt-fn (into prefix admin-block))))


;; ## Challenge 14
;;
;; I don't have a clue how to do this. :(
;;
;; TODO: Come back to this later.

(defn challenge-14 []
  )

;; ## Challenge 15 -- PKCS#7 padding validation
;;
;; Write a function that takes a plaintext, determines if it has valid
;; PKCS#7 padding, and strips the padding off.

(defn challenge-15 []
  (let [root (common/str->bytes "ICE ICE BABY")
        valid (into root (repeat 4 4))
        invalid-1 (into root (repeat 4 5))
        invalid-2 (into root [1 2 3 4])
        remove-padding (partial common/remove-pkcs7-padding 16)]

    (print valid)
    (when (remove-padding valid)
      (println "valid"))

    (print invalid-1)
    (try
      (remove-padding invalid-1)
      (catch IllegalArgumentException e
        (println "invalid")))

    (print invalid-2)
    (try
      (remove-padding invalid-2)
      (catch IllegalArgumentException e
        (println "invalid")))))


;; ## Challenge 16 -- CBC bitflipping attacks

(defn- escape-str [str]
  (-> str
      (s/replace #";" "%3B")
      ( s/replace #"=" "%3D")))

(defn- create-cookie [userdata]
  (str
   "comment1=cooking%20MCs;userdata="
   (escape-str userdata)
   ";comment2=%20like%20a%20pound%20of%20bacon"))

(defn encrypt-cookie [ctx userdata]
  (cbc-encrypt-msg (:key ctx) (:iv ctx) (common/str->bytes (create-cookie userdata))))

(defn decrypt-cookie [ctx ciphertext]
  (let [plaintext (cbc-decrypt-msg (:key ctx) (:iv ctx) ciphertext)
        plaintext-str (common/bytes->ascii plaintext)]
    {:success (re-find #";admin=true" plaintext-str)
     :msg plaintext-str}))

;; ### What we're trying to do...
;;
;; produce an input-string with ';admin=true' in it.
;;
;; How can we do this?
;;
;; 1. find how many bytes of padding are required until we enter a new block (conveniently, this falls exactly on the block-boundary already)
;; 2. determine the positions of the characters we want to change (';' + '=')
;; 3. mangle the previous block of ciphertext such that when it is XOR'd with the decrypted block, we will have the desired values set.
;;
;; Recall that A ^ B ^ A = B; therefore B = A ^ x -> A ^ B = x.
;; Therefore, if we want to modify `;min=ue -> %3Bmin%3Due`, we need
;; to modify the following bytes in the block: `***---***----------`

(defn- do-xor [replace before after]
  (bit-xor (bit-xor replace (int before)) (int after)))

;; Edit the preceeding block such that when the previous block's
;; ciphertext is XOR'd with the current block's deciphered text, we
;; get the characters we want.
(defn- flip-bits
  [cb]
  (let [mangled-block (-> cb
                          (assoc 0 (do-xor (nth cb 0) \% \;))
                          (assoc 1 (do-xor (nth cb 1) \3 \a))
                          (assoc 2 (do-xor (nth cb 2) \B \d))
                          (assoc 6 (do-xor (nth cb 6) \% \=))
                          (assoc 7 (do-xor (nth cb 7) \3 \t))
                          (assoc 8 (do-xor (nth cb 8) \D \r)))]
    (clojure.pprint/pprint mangled-block)
    mangled-block))

(defn challenge-16 []
  (let [context {:key (common/get-random-key 16) :iv (common/get-random-key 16)}
        encrypt-fn (partial encrypt-cookie context)
        decrypt-fn (partial decrypt-cookie context)
        ciphertext (encrypt-fn ";min=ue")
        blocks (map vec (partition-all 16 ciphertext))]
    (-> (into [] (first blocks))
        (into (flip-bits (second blocks)))
        (into (drop 32 ciphertext))
        (decrypt-fn))))

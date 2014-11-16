(ns cryptopals.set1
  (:require [clojure.string :as s]
            [clojure.java.io :as io])
  (:import java.util.Base64
           (javax.crypto Cipher KeyGenerator SecretKey)
           (javax.crypto.spec SecretKeySpec)
           (java.security SecureRandom)))

(def common-english-words #{"the" "be" "to" "of" "and" "a" "in" "that"
"have" "I" "it" "for" "not" "on" "with" "he" "as" "you" "do" "at"
"this" "but" "his" "by" "from" "they" "we" "say" "her" "she" "or" "an"
"will" "my" "one" "all" "would" "there" "their" "what" "so" "up" "out"
"if" "about" "who" "get" "which" "go" "me" "when" "make" "can" "like"
"time" "no" "just" "him" "know" "take" "people" "into" "year" "your"
"good" "some" "could" "them" "see" "other" "than" "then" "now" "look"
"only" "come" "its" "over" "think" "also" "back" "after" "use" "two"
"how" "our" "work" "first" "well" "way" "even" "new" "want" "because"
"any" "these" "give" "day" "most" "us"})

;; this needs some tweaking:
;; adapted from http://en.wikipedia.org/wiki/Letter_frequency
(def english-freq-table {\space 20,
                         \e 15,
                         \t 10,
                         \a 8,
                         \o 8,
                         \i 8,
                         \n 6,
                         \s 6,
                         \h 6,
                         \r 5,
                         \d 4,
                         \l 4,
                         \c 2,
                         \u 2,
                         \m 2,
                         \w 2,
                         \f 2,
                         \g 2,
                         \y 1,
                         \p 1,
                         \b 1})

(defn remove-linebreaks [str]
  (s/replace str #"\n" ""))

(defn str->bytes [str]
  (seq (. str getBytes)))

(defn hex->int [s]
  (Integer/parseInt s 16))

(defn int->hex [i]
  (format "%02x" i))

(defn hex->bytes [h]
  (let [octets (map #(apply str %) (partition-all 2 h))]
    (map #(Integer/parseInt % 16) octets)))

(defn bytes->hex [b]
  (apply str (map int->hex b)))

(defn bytes->ascii [b]
  (apply str (map char b)))


;; Challenge 1

(def ^:private b64-table (vec
                (concat
                 (map char
                      (concat
                       (range (int \A) (inc (int \Z)))
                       (range (int \a) (inc (int \z)))
                       (range (int \0) (inc (int \9)))))
                 [\+ \/])))


(defn- combine-bytes [bytes]
  (reduce #(+ (bit-shift-left % 8) %2) bytes))

;; this doesn't add padding
;; sounds like a problem for future matt...
(defn- chunk->b64 [chunk]
  (loop [c chunk acc []]
    (if (= (count acc) 4)
      (reverse acc)
      (do
        (let [sextet (bit-and c 0x3f)
              remainder (bit-shift-right c 6)
              b64-digit (get b64-table sextet)]
          (recur remainder (conj acc b64-digit)))))))

(defn hex->b64 [b]
  (let [chunks (map combine-bytes (partition-all 3 (hex->bytes b)))]
    (apply str (mapcat chunk->b64 chunks))))

;; Well, that was easier, although somewhat unsatisfying...

(defn b64-decode [^String b64-string]
  (seq (. (Base64/getDecoder) decode b64-string)))

(defn b64-encode [byte-seq]
  (. (Base64/getEncoder) encodeToString (byte-array byte-seq)))


;; Challenge 2

(defn fixed-xor [input key]
  (let [pairs (map vector input key)]
    (map #(bit-xor (first %) (last %)) pairs)))

;; Challenge 3

(defn- create-all-possible [input]
  (for [x (range 1 255)]
    {:key x :str (bytes->ascii (fixed-xor input (repeat x)))}))

(defn- is-nonprintable? [c]
  ( or (< (int c) 32) (> (int c) 126)))

(defn- count-english-words [str]
  (let [words (s/split str #"\s+")]
    (count (filter common-english-words words))))

(defn- is-english-plaintext? [str]
  (> (count-english-words str) 0))

(defn- score-string [str]
  (reduce +
          (map
           (fn [c]
             (if (is-nonprintable? c)
               -100
               (get english-freq-table c 0)))
           (s/lower-case str))))

(defn- score-all-single-byte-decrypts [input]
  (->> input
       (create-all-possible)
       (map #(assoc % :score (score-string (:str %))))
       (sort-by :score)
       (reverse)))

(defn bruteforce-single-byte-xor [input]
  (->> (score-all-single-byte-decrypts input)
       (first)
       (:str)))


;; challenge 4

(defn challenge-4 []
  (let [strings (s/split (slurp (io/resource "4.txt")) #"\n")
        byte-strings (map hex->bytes strings)
        all-possibilities (reverse (sort-by :score (mapcat score-all-single-byte-decrypts byte-strings)))]
    (println (first (map :str all-possibilities)))))


;; Challenge 5

(defn encrypt-repeating-xor [plaintext-bytes key-bytes]
  (let [key-seq (cycle key-bytes)]
    (map #(bit-xor % %2) plaintext-bytes key-seq)))


;; Challenge 6

(defn- count-high-bits
  "Count the number of high bits in a byte."
  [b]
  (loop [acc 0 rem b]
    (if (= rem 0)
      acc
      (recur (+ acc (bit-and rem 1)) (bit-shift-right rem 1)))))

(defn transpose [input block-size]
  (for [i (range 0 block-size)] (map #(nth % i) (partition block-size input))))

(defn hamming-distance
  "compute bitwise hamming distance between two byte-seqs; assumes both seqs are of equal size"
  [a b]
  (reduce + (map #(count-high-bits (bit-xor % %2)) a b)))

;; Interestingly, this is a completely terrible way to guess the key
;; length. Was the challenge lying when it suggested this?
(defn- score-key-length [input key-length]
  (let [chunks (partition-all key-length input)
        a (first chunks)
        b (second chunks)]
    (double (/ (hamming-distance a b) key-length))))

(defn- score-key-length-avg [input key-length]
  (let [chunks (partition-all key-length input)
        a (first chunks)
        b (nth chunks 1)
        c (nth chunks 2)
        d (nth chunks 3)
        fn-norm (fn [x y] (/ (hamming-distance x y) key-length))]
    (double (/ (+ (fn-norm a b) (fn-norm a c) (fn-norm a d) (fn-norm b c) (fn-norm b d) (fn-norm c d)) 6))))

(defn- guess-key-lengths
  "Guess key lengths based on minimum normalized hamming distances. Smaller scores are better."
  [input]
  (map :length
       (sort-by :score
                (map #(hash-map :length % :score (score-key-length-avg input %)) (range 2 41)))))

(defn- find-best-key-for-block [block]
  (->> (score-all-single-byte-decrypts block)
       (first)
       (:key)))

(defn- guess-key [input block-size]
  (let [blocks (transpose input block-size)]
    (map find-best-key-for-block blocks)))

(defn- try-decrypt [input block-size]
  (let [key (guess-key input block-size)]
    {:key (bytes->ascii key) :msg (bytes->ascii (encrypt-repeating-xor input key))}))

(defn run6 []
  (let [input (b64-decode (remove-linebreaks (slurp (io/resource "6.txt"))))
        key-length (first (guess-key-lengths input))
        result (try-decrypt input key-length)]
    (println (str "Key: " (:key result)))
    (println (str "Length: " (count (:key result))))
    (println)
    (println (:msg result))))


;; Challenge 7
;; Remember that everything I have takes seqs of bytes

(defn b64-slurp [f]
  (b64-decode (remove-linebreaks (slurp (io/resource f)))))

(def ^:private aes-ecb "AES/ECB/NoPadding")

(defn get-cipher [mode key]
  (let [key-spec (SecretKeySpec. (byte-array key) "AES")
        cipher (Cipher/getInstance aes-ecb)]
    (.init cipher mode key-spec)
    cipher))

(defn aes-ecb-encrypt [text key]
  (let [plaintext (byte-array text)
        cipher (get-cipher Cipher/ENCRYPT_MODE key)]
    (vec (.doFinal cipher plaintext))))

(defn aes-ecb-decrypt [text key]
  (let [cipher (get-cipher Cipher/DECRYPT_MODE key)
        ciphertext (byte-array text)]
    (vec (.doFinal cipher ciphertext))))

(defn run7 []
  (aes-ecb-decrypt (b64-slurp "7.txt") "YELLOW SUBMARINE"))


;; Challenge 8

(defn find-patterns [b]
  (let [block-freqs (frequencies (partition-all 16 b))
         counts (map second block-freqs)]
    (apply max counts)))

 (defn run8 []
   (let [strings (s/split (slurp (io/resource "8.txt")) #"\n")
         byte-strings (map hex->bytes strings)]
     (bytes->hex
      (first
       (filter
        (fn [x] (> (find-patterns x) 1))
        byte-strings)))))


;; Challenge 9

(defn add-padding [length b]
  (let [num-padding-bytes (- length (count b))
        result (vec b)]
    (if (<= num-padding-bytes 0)
      b
      (into result (repeat num-padding-bytes num-padding-bytes)))))


;; Challenge 10

(defn cbc-encrypt-msg [key iv plaintext]
  (loop [blocks (partition-all 16 plaintext)
         prev-block iv
         ciphertext []]
    (if (empty? blocks)
      ciphertext
      (let [block (add-padding 16 (first blocks))
            xored-block (fixed-xor prev-block block)
            encrypted-block (aes-ecb-encrypt xored-block key)]
        (recur (rest blocks) encrypted-block (into ciphertext encrypted-block))))))

(defn cbc-decrypt-msg [key iv ciphertext]
  (loop [blocks (partition-all 16 ciphertext)
         prev-block iv
         plaintext []]
    (if (empty? blocks)
      plaintext
      (let [block (add-padding 16 (first blocks))
            decrypted-block (aes-ecb-decrypt block key)
            plaintext-block (fixed-xor decrypted-block prev-block)]
        (recur (rest blocks) block (into plaintext plaintext-block))))))

(defn run10 []
  (let [input (b64-slurp "10.txt")
        key (str->bytes "YELLOW SUBMARINE")
        iv (repeat 16 0)
        plaintext (cbc-decrypt-msg input key iv)]
    (println (apply str (mapcat #(map char %) plaintext)))))


;; Challenge 11

(defn ecb-decrypt-msg [key ciphertext]
  (mapcat (fn [x] (aes-ecb-decrypt x key)) (partition-all 16 ciphertext)))

(defn ecb-encrypt-msg [key plaintext]
  (mapcat (fn [x] (aes-ecb-encrypt (add-padding 16 x) key)) (partition-all 16 plaintext)))

(defn get-random-key []
  (repeatedly 16 #(rand-int 255)))

(defn apply-random-padding [input]
  (let [prefix-length (+ 5 (rand-int 7))
        suffix-length (+ 5 (rand-int 7))]
    (-> []
     (into (repeat prefix-length 0))
     (into input)
     (into (repeat suffix-length 0)))
    ))

(defn rand-encrypt-msg [raw-input]
  (let [mode (rand-nth [:cbc :ecb])
        key (get-random-key)
        iv (get-random-key)
        input (apply-random-padding raw-input)]
    (condp = mode
      :cbc (do (println "picked cbc") (cbc-encrypt-msg key iv input))
      :ecb (do (println "picked ecb") (ecb-encrypt-msg key input))
      )))

(defn encryption-oracle [encryption-fn]
  (let [plaintext (repeat 256 (int \A))
        ciphertext (encryption-fn plaintext)
        max-repeated-blocks (apply max (map second (frequencies (partition-all 8 ciphertext))))]
    (if (> max-repeated-blocks 1)
      :ecb
      :cbc)))


;; challenge 12

(def context (atom {:key (get-random-key)
                    :secret (b64-slurp "12.txt")}))

(defn known-bytes [num-bytes]
  (vec (repeat num-bytes (int \A))))

(defn c12-encrypt [ctx plaintext]
  (ecb-encrypt-msg (:key @ctx) (into (vec plaintext) (:secret @ctx))))

;; The length of an ecb output is always a multiple of the block size.
;; We can exploit this by adding bytes to the input until the output
;; size changes.
;;
;; The block-size is the delta between the two output sizes.
(defn guess-block-length [encrypt-fn]
  (let [initial (count (encrypt-fn (known-bytes 0)))]
    (loop [length 0]
      (let [next (count (encrypt-fn (known-bytes (inc length))))]
        (if (not= initial next)
          (- next initial)
          (recur (inc length)))))))

(defn block-for-position [block-size position]
  (quot position block-size))

(defn get-block-for-position [block-size position ciphertext]
  (nth (partition-all block-size ciphertext) (block-for-position block-size position)))

(defn padding-for-position [block-size plaintext]
  (let [plaintext-length (count plaintext)]
    (known-bytes (- (dec block-size) (mod plaintext-length block-size)))))

;; Because ECB is stateless, all identical input blocks will produce
;; identical output blocks.
;;
;; Here we are creating a block containing 15 fixed values with the
;; last value containing all possible bytes. We can use this to
;; comapre against the first block of ciphertext to decrypt the 1st
;; byte of the secret.
(defn create-attack-dictionary [encrypt-fn block-size known-plaintext]
  (let [position (count known-plaintext)
        prefix (into (padding-for-position block-size known-plaintext) known-plaintext)
        interesting-bytes (* block-size (inc (block-for-position block-size position)))]
    (apply hash-map
           (reduce into [] (for [x (range 0 256)]
                             [(get-block-for-position block-size position (encrypt-fn (conj prefix x))) x])))))

(defn create-attack-ciphertext [encrypt-fn block-size known-plaintext]
  (let [position (count known-plaintext)
        prefix (padding-for-position block-size known-plaintext)]
    (get-block-for-position block-size position (encrypt-fn prefix))))

(defn c12-get-next-byte [encrypt-fn block-size plaintext]
  (get
   (create-attack-dictionary encrypt-fn block-size plaintext)
   (create-attack-ciphertext encrypt-fn block-size plaintext)))

;; So this is an interesting problem. Because of the way that pkcs#7
;; padding works, the value of the last padding digit will change as
;; our oracle function runs. This attack exploits the fact that the
;; secret portion of the message does not change, so the variable
;; padding values break it.
;;
;; Not sure what to do about this...
(defn run12 [encrypt-fn block-size]
  (loop [x 144 plaintext [(c12-get-next-byte encrypt-fn block-size [])]]
    (if (nil? (last plaintext))
      (drop-last plaintext)
      (recur (dec x) (conj plaintext (c12-get-next-byte encrypt-fn block-size plaintext))))))


;; challenge 13

(defn parse-kv [kvstr]
  (reduce #(assoc % (keyword (nth %2 1)) (nth %2 2)) {} (re-seq #"(\w+)=([^&]+)" kvstr)))

(defn profile-for [email]
  (let [sanitized-email (s/replace email #"(&|=)" "")]
    (str "email=" sanitized-email "&uid=10&role=user")))

(defn >c13 [email]
  (ecb-encrypt-msg (:key @context) (str->bytes (profile-for email))))

(defn <c13 [ciphertext]
  (parse-kv (bytes->ascii (strip-pkcs7-padding (ecb-decrypt-msg (:key @context) ciphertext)))))

;; We can exploit the fact that we know the layout of the plaintext.
;;
;; - Since the layout of fields in the plaintext is fixed, we pick an
;; email address such that the text 'admin' appears in its own padded
;; block.
;;
;; - Then we select an email address such that the plaintext 'user'
;; occurs in its own padded block.
;;
;;- In order to change this to 'admin', we simply swap these two
;; blocks out. Provided that there's no checksum on the message, we
;; have successfully modified the plaintext.
(defn run13 []
  (let [admin-ciphertext (nth (partition-all 16 (>c13 (str (apply str (repeat 10 \B)) "admin" (apply str (repeat 11 (char 11)))))) 1)
        prefix (vec (take 32 (>c13 (apply str (repeat 13 \z)))))]
    (<c13 (into prefix admin-ciphertext))))


;; challenge 15
;;
;; Write a function that takes a plaintext, determines if it has valid
;; PKCS#7 padding, and strips the padding off.

(defn- validate-padding [block-size last-block]
  (let [padding-length (last last-block)
        has-padding (< padding-length block-size)]
    (if has-padding
      (let [num-padding-bytes (count
                               (filter
                                #(= % padding-length)
                                (take-last padding-length last-block)))]
        {:is-valid (= num-padding-bytes padding-length)
         :length padding-length})
      {:is-valid true
       :length 0})))

(defn unpad-plaintext [block-size plaintext]
  (let [last-block (last (partition-all block-size plaintext))
        v (validate-padding block-size last-block)]
    (if (:is-valid v)
      {:is-valid true
       :msg (drop-last (:length v) plaintext)}
      {:is-valid false})))

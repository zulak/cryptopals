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

;; Challenge 9

(defn challenge-9 [block-size plaintext]
  (let [plaintext-bytes (str->bytes plaintext)]
    (common/add-pkcs7-padding block-size plaintext-bytes)))


;; Challenge 10

(defn cbc-encrypt-msg [key iv plaintext]
  (loop [blocks (partition-all 16 (add-padding 16 plaintext))
         prev-block iv
         ciphertext []]
    (if (empty? blocks)
      ciphertext
      (let [block (first blocks)
            xored-block (set1/fixed-xor block prev-block)
            encrypted-block (common/aes-ecb-encrypt xored-block key)]
        (recur (rest blocks) encrypted-block (into ciphertext encrypted-block))))))

(defn cbc-decrypt-msg [key iv ciphertext]
  (loop [blocks (partition-all 16 ciphertext)
         prev-block iv
         plaintext []]
    (if (empty? blocks)
      plaintext
      (let [block (first blocks)
            decrypted-block (common/aes-ecb-decrypt block key)
            plaintext-block (set1/fixed-xor decrypted-block prev-block)]
        (recur (rest blocks) block (into plaintext plaintext-block))))))

(defn run10 []
  (let [input (common/b64-slurp "10.txt")
        key (common/str->bytes "YELLOW SUBMARINE")
        iv (repeat 16 0)
        plaintext (cbc-decrypt-msg input key iv)]
    (println (apply str (mapcat #(map char %) plaintext)))))


;; Challenge 11

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

(def context (atom {:key (get-random-key 16)
                    :iv (get-random-key 16)
                    :secret (common/b64-slurp "12.txt")
                    :random-prefix (repeatedly (rand-int 32) #(rand-int 256))}))

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

(defn padding-for-position [block-size offset plaintext]
  (let [plaintext-length (count plaintext)]
    (known-bytes (+ offset (- (dec block-size) (mod plaintext-length block-size))))))

;; Because ECB is stateless, all identical input blocks will produce
;; identical output blocks.
;;
;; Here we are creating a block containing 15 fixed values with the
;; last value containing all possible bytes. We can use this to
;; comapre against the first block of ciphertext to decrypt the 1st
;; byte of the secret.
(defn create-attack-dictionary [encrypt-fn block-size padding-offset known-plaintext]
  (let [position (count known-plaintext)
        prefix (into (padding-for-position block-size padding-offset known-plaintext) known-plaintext)
        interesting-bytes (* block-size (inc (block-for-position block-size position)))]
    (apply hash-map
           (reduce into [] (for [x (range 0 256)]
                             [(get-block-for-position block-size position (encrypt-fn (conj prefix x))) x])))))

(defn create-attack-ciphertext [encrypt-fn block-size padding-offset known-plaintext]
  (let [position (count known-plaintext)
        prefix (padding-for-position block-size padding-offset known-plaintext)
        block (get-block-for-position block-size position (encrypt-fn prefix))]
    block))

(defn c12-get-next-byte [encrypt-fn block-size plaintext]
  (get
   (create-attack-dictionary encrypt-fn block-size 0 plaintext)
   (create-attack-ciphertext encrypt-fn block-size 0 plaintext)))

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
      (drop-last 2 plaintext)
      (recur (dec x) (conj plaintext (c12-get-next-byte encrypt-fn block-size plaintext))))))


;; challenge 13

(defn strip-pkcs7-padding [in]
  in)

(defn parse-kv [kvstr]
  (reduce #(assoc % (keyword (nth %2 1)) (nth %2 2)) {} (re-seq #"(\w+)=([^&]+)" kvstr)))

(defn profile-for [email]
  (let [sanitized-email (s/replace email #"(&|=)" "")]
    (str "email=" sanitized-email "&uid=10&role=user")))

(defn >c13 [email]
  (ecb-encrypt-msg (:key @context) (common/str->bytes (profile-for email))))

(defn <c13 [ciphertext]
  (parse-kv (common/bytes->ascii (strip-pkcs7-padding (common/ecb-decrypt-msg (:key @context) ciphertext)))))

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


;; challenge 14

;; I'm assuming that random-prefix and random-key are fixed for all encryptions...
;; AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

(defn c14-encrypt [ctx attacker-plaintext]
  (let [plaintext (-> (vec (:random-prefix @ctx))
                      (into attacker-plaintext)
                      (into (:secret @ctx)))]
    (ecb-encrypt-msg (:key @ctx) plaintext)))

;; find the indices of the first pair of adjacent duplicates
(defn- find-adj-dup [coll]
  (loop [result 0 rem coll]
    (let [f (first rem)
          s (second rem)]
      (cond
       (nil? f) nil
       (nil? s) nil
       (= f s) [result (inc result)]
       :else (recur (inc result) (rest rem))))))

;; find the required additional padding to push the place
;; attacker-controlled bytes into a fresh block
(defn find-required-padding [block-size encrypt-fn]
  (loop [x block-size]
    (let [ciphertext (encrypt-fn (repeat x (int \z)))
          blocks (partition-all block-size ciphertext)
          adj-blocks (find-adj-dup blocks)]
      (cond
       (> x (* 4 block-size)) nil
       (not (nil? adj-blocks)) {:block-offset (first adj-blocks),
                                :req-padding (- x (* 2 block-size))}
       :else (recur (inc x))))))

;; this is pretty much an identical solution to c12, except now we
;; need to peel off the first few blocks and prepend a few extra bytes
;; to our prefix...
(defn c14-get-next-byte [encrypt-fn block-size block-offset padding-offset plaintext]
  (get
   (create-attack-dictionary #(drop (* block-size block-offset) (encrypt-fn %)) block-size padding-offset plaintext)
   (create-attack-ciphertext #(drop (* block-size block-offset) (encrypt-fn %)) block-size padding-offset plaintext)))

(defn run14 [encrypt-fn block-size]
  (let [{:keys [req-padding block-offset]} (find-required-padding block-size encrypt-fn)]
    (loop [x 144 plaintext [(c14-get-next-byte encrypt-fn block-size block-offset req-padding [])]]
      (if (nil? (last plaintext))
        (drop-last 2 plaintext)
        (recur (dec x) (conj plaintext (c14-get-next-byte encrypt-fn block-size block-offset req-padding plaintext)))))))


;; challenge 15
;;
;; Write a function that takes a plaintext, determines if it has valid
;; PKCS#7 padding, and strips the padding off.

(defn- validate-padding [block-size last-block]
  (let [padding-length (last last-block)
        num-padding-bytes (count
                             (filter
                              #(= % padding-length)
                              (take-last padding-length last-block)))]
    {:is-valid (and (= block-size (count last-block)) (= num-padding-bytes padding-length))
     :length padding-length}))

(defn remove-padding [block-size plaintext]
  (let [last-block (last (partition-all block-size plaintext))
        v (validate-padding block-size last-block)]
    (if (:is-valid v)
      {:is-valid true
       :msg (drop-last (:length v) plaintext)}
      {:is-valid false})))


;; challenge 16

(defn- escape-str [str]
  (-> str
      (s/replace #";" "%3B")
      ( s/replace #"=" "%3D")))

(defn- create-cookie [userdata]
  (str "comment1=cooking%20MCs;userdata=" (escape-str userdata) ";comment2=%20like%20a%20pound%20of%20bacon"))

(defn encrypt-cookie [ctx userdata]
  (cbc-encrypt-msg (:key @ctx) (:iv @ctx) (common/str->bytes (create-cookie userdata))))

(defn decrypt-cookie [ctx ciphertext]
  (let [plaintext (cbc-decrypt-msg (:key @ctx) (:iv @ctx) ciphertext)]
    (println (common/bytes->ascii plaintext))
    (re-find #";admin=true" (common/bytes->ascii plaintext))))

;; what we're trying to do...
;;
;; produce an input-string with ';admin=true' in it.
;;
;; How can we do this?
;;
;; 1. find how many bytes of padding are required until we enter a new block (conveniently, this falls exactly on the block-boundary already)
;; 2. determine the positions of the characters we want to change (';' + '=')
;; 3. mangle the previous block of ciphertext such that when it is XOR'd with the decrypted block, we will have the desired values set.
;; recall that A ^ B ^ A = B; therefore B = A ^ x -> A ^ B = x

;; ;min=ue -> %3Bmin%3Due
;; we need to modify the following bytes: ***---***----------
;;
;; (75 42 82 -127 -119 83 51 97 8 48 -84 112 66 -99 -78
(def corrupt-ciphertext [78 78 16 -113 53 -109 -124 -109 -29 56 94 93 -47 -19 21 -47
                         (bit-xor 75 (int \;)) -77 -72 115 47 3 58 71 74 -102 48 -44 16 3 107 -59
                         75 42 82 -127 -119 83 51 97 8 48 -84 112 66 -99 -78 85 60 96 -91 122 -12 31 42 -18 -100 -108 53 74 -27 -102 -9 -40 120 84 86 -95 -18 54 25 -67 -39 -88 18 -44 -118 -59 20 -84 -45 -76 99 -13 -79 29 114 -49 -54 10 -104 -106 108 -88 -65 -75])

;; TODO: generate this block automatically.
(def mask [(bit-and 0xff (bit-xor (bit-xor 246 (int \%)) (int \;))) (bit-xor (bit-xor 110 (int \3)) (int \a)) (bit-xor (bit-xor (int \B) 18) (int \d))  -89 -76 49 (bit-xor (bit-xor -27 (int \%)) (int \=)) (int \t) (int \r) 0 0 0 0 0 0 0])

(defn mangle []
  (let [ciphertext (encrypt-cookie context ";min=ue")
        blocks (partition-all 16 ciphertext)
        evil-block mask]
    (println (second blocks))
    (-> (into [] (first blocks))
        (into evil-block)
        (into (drop 32 ciphertext)))))

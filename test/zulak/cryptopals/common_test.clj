(ns zulak.cryptopals.common-test
  (:require [clojure.test :refer :all]
            [clojure.string :as s]
            [clojure.java.io :as io]
            [zulak.cryptopals.common :refer :all]))

(deftest can-filter-unprintable-characters
  (testing "Unprintable charcters are filtered"
    (is (= "\n" (bytes->ascii (range 0 31))))))

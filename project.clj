(defproject buddy "0.4.0"
  :description "Security library for Clojure"
  :url "https://github.com/funcool/buddy"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[buddy/buddy-core "0.4.0"]
                 [buddy/buddy-sign "0.4.0"]
                 [buddy/buddy-auth "0.4.0"]
                 [buddy/buddy-hashers "0.4.0"]]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"])

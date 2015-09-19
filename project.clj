(defproject buddy "0.7.0"
  :description "Security library for Clojure"
  :url "https://github.com/funcool/buddy"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[buddy/buddy-core "0.7.0"]
                 [buddy/buddy-sign "0.7.0"]
                 [buddy/buddy-auth "0.7.0"]
                 [buddy/buddy-hashers "0.7.0"]]
  :plugins [[lein-ancient "0.6.7"]]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"])

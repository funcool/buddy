(defproject buddy "1.0.0"
  :description "Security library for Clojure"
  :url "https://github.com/funcool/buddy"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[buddy/buddy-core "0.13.0" :exclusions [org.clojure/clojure]]
                 [buddy/buddy-auth "1.1.0" :exclusions [org.clojure/clojure]]
                 [buddy/buddy-hashers "0.14.0" :exclusions [org.clojure/clojure]]
                 [buddy/buddy-sign "1.1.0" :exclusions [org.clojure/clojure]]]
  :plugins [[lein-ancient "0.6.10"]]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"])

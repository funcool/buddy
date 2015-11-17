(defproject buddy "0.8.1"
  :description "Security library for Clojure"
  :url "https://github.com/funcool/buddy"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[buddy/buddy-core "0.8.1" :exclusions [org.clojure/clojure]]
                 [buddy/buddy-auth "0.8.1" :exclusions [org.clojure/clojure]]
                 [buddy/buddy-hashers "0.9.0" :exclusions [org.clojure/clojure]]
                 [buddy/buddy-sign "0.8.1" :exclusions [org.clojure/clojure]]]
  :plugins [[lein-ancient "0.6.7"]]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"])

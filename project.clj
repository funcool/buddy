(defproject buddy "0.1.0-beta1"
  :description "Authentication, Authorization and Signing library."
  :url "https://github.com/niwibe/buddy"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0.txt"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [org.clojure/algo.monads "0.1.4"]
                 [ring/ring-core "1.2.1"]
                 [commons-codec/commons-codec "1.8"]
                 [com.taoensso/nippy "2.4.1"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :plugins [[codox "0.6.6"]]
  :codox {:output-dir "doc/api"
          :src-dir-uri "http://github.com/niwibe/buddy/blob/master/"
          :src-linenum-anchor-prefix "L"})

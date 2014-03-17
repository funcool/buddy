(defproject buddy "0.1.0-beta4"
  :description "Authentication, Authorization and Signing library."
  :url "https://github.com/niwibe/buddy"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0.txt"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [org.clojure/algo.monads "0.1.4"]
                 [ring/ring-core "1.2.1"]
                 [commons-codec/commons-codec "1.8"]
                 [com.taoensso/nippy "2.4.1"]
                 [clojurewerkz/scrypt "1.1.0"]
                 [org.bouncycastle/bcprov-jdk15 "1.46"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :plugins [[codox "0.6.6"]]
  :codox {:output-dir "doc/api"
          :src-dir-uri "http://github.com/niwibe/buddy/blob/master/"
          :src-linenum-anchor-prefix "L"}
  :profiles {:uberjar {:aot :all}
             :example {:dependencies [[compojure "1.1.6"]
                                      [ring "1.2.1"]]}
             :sessionexample [:example
                              {:source-paths ["examples/sessionexample/src"]
                               :resource-paths ["examples/sessionexample/resources"]
                               :target-path "examples/sessionexample/target/%s"
                               :main ^:skip-aot sessionexample.core}]
             :oauthexample [:example
                            {:dependencies [[clj-http "0.7.9"]
                                            [hiccup "1.0.5"]
                                            [org.clojure/data.json "0.2.4"]]
                             :source-paths ["examples/oauthexample/src"]
                             :resource-paths ["example/oauthexample/resources"]
                             :target-path "examples/oauthexample/target/%s"
                             :main ^:skip-aot oauthexample.core}]
             :1.6 {:dependencies [[org.clojure/clojure "1.6.0-beta2"]]}})

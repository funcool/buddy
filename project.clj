(defproject buddy "0.2.0b1"
  :description "Security library for Clojure"
  :url "https://github.com/niwibe/buddy"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0.txt"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/algo.monads "0.1.5"]
                 [ring/ring-core "1.2.2"]
                 [commons-codec/commons-codec "1.9"]
                 [com.taoensso/nippy "2.6.3"]
                 [clojurewerkz/scrypt "1.1.0"]
                 [clj-time "0.7.0"]
                 [swiss-arrows "1.0.0"]
                 [cheshire "5.3.1"]
                 [org.bouncycastle/bcprov-jdk15on "1.50"]
                 [org.bouncycastle/bcpkix-jdk15on "1.50"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :plugins [[codox "0.6.7"]
            [lein-cloverage "1.0.2"]]
  :codox {:output-dir "doc/api"
          :src-dir-uri "http://github.com/niwibe/buddy/blob/master/"
          :src-linenum-anchor-prefix "L"}
  :profiles {:uberjar {:aot :all}
             :bench {:dependencies [[criterium "0.4.3"]]
                     :source-paths ["benchmarks/"]
                     :main ^:skip-aot buddy.benchmarks}
             :example {:dependencies [[compojure "1.1.6"]
                                      [ring "1.2.2"]]}
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
                             :main ^:skip-aot oauthexample.core}]})

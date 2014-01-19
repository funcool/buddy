(defproject sessionexample "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0.txt"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [compojure "1.1.6"]
                 ;; [ring/ring-core "1.2.1"]
                 [ring "1.2.1"]
                 [org.clojure/algo.monads "0.1.4"]
                 [commons-codec/commons-codec "1.8"]
                 [com.taoensso/nippy "2.4.1"]]
  :source-paths ["src" "../../src/clojure"]
  :java-source-paths ["../../src/java"]
  :main ^:skip-aot sessionexample.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})

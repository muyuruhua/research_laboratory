{application,eleveldb,
             [{description,"Erlang wrapper to Basho-modified leveldb store"},
              {vsn,"riak_kv-3.0.0+build.718.ref0ad275c"},
              {registered,[]},
              {applications,[kernel,stdlib]},
              {env,[{total_leveldb_mem_percent,15},
                    {use_bloomfilter,true},
                    {compression,snappy}]},
              {modules,[eleveldb,eleveldb_bump]}]}.

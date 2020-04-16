# make 404 statistics on orig_h
# In every 10 minutes
#  if the count of 404 response > 2
#  and if the 404 ratio > 20% (404 ratio = 404 response/all response)
#  and if (the unique count of url response 404 / if the count of 404 response ) > 0.5
#  then output ”x.x.x.x is a scanner with y scan attemps on z urls” where
#  x.x.x.x is the orig_h, y is the count of 404 response , z is the unique count of url response 404

event zeek_init(){
    local Rall = SumStats::Reducer($stream="allresponse", $apply=set(SumStats::UNIQUE));
    local R404 = SumStats::Reducer($stream="404response", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="scaner_reporter",
                      $epoch=10min,
                      $reducers=set(Rall,R404),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
                            local r_all = result["allresponse"];
                            local r_404 = result["404response"];
                            if(r_404$num > 2){
                                if(r_404$num / r_all$num > 0.2){
                                    if(r_404$unique / r_all$num > 0.5){
                                        print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, r_404$num, r_404$unique);
                                    }
                                }
                            }
                       }
]);
}

event http_reply(c: connection, version: string, code: count, reason: string){
    SumStats::observe("allresponse", [$host=c$id$orig_h], [$str=reason]);
    if(code == 404){
		    SumStats::observe("404response", [$host=c$id$orig_h], [$str=reason]);
	}
}

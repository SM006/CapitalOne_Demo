module SSRF;

export {
    redef enum Notice::Type += {
        Metadata_Access
    };
}

event http_request(c: connection, method: string, original_URI: string,
                    unescaped_URI: string, version: string)
    {
    if ( c$id$resp_h == 169.254.169.254 )
        {
        NOTICE([$note=SSRF::Metadata_Access,
                $msg=fmt("Possible SSRF: AWS EC2 metadata service accessed by %s (Requested URI: %s)",
                         c$id$orig_h, original_URI),
                $conn=c]);
        }
    }

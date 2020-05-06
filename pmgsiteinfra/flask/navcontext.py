from flask import current_app, request

class NavContext(object):
    def __init__(self, page_size):
        self.page_size = page_size

    @staticmethod
    def req_offset():
        ret = request.args.get('offset')
        try:
            return int(ret) if ret else 0
        except ValueError:
            return 0

    @staticmethod
    def req_page():
        return int(NavContext.req_offset() / page_size) + 1
    
    def ctx(self, result_len, **kwargs):
        result_offset = NavContext.req_offset()
        idx_fr = result_offset + 1
        idx_to = result_offset + result_len
        prev_offset = None if result_offset <= 0 else result_offset - self.page_size if result_offset > self.page_size else 0
        next_offset = result_offset + self.page_size if result_len >= self.page_size else None
        return dict(idx_fr=idx_fr, idx_to=idx_to, prev_offset=prev_offset, next_offset=next_offset, 
                res=dict(offset=0, **kwargs),
                prv=dict(offset=prev_offset, **kwargs),
                nxt=dict(offset=next_offset, **kwargs),
                **kwargs,)





import pyclamd
import magic
#checks file headers to see if it is the file type it says it is
#still weak to crafted payloads!!
#done by alexander
def allowed_mime_type(file):
    # Read the first 2048 bytes to detect MIME
    mime = magic.from_buffer(file.stream.read(2048), mime=True)
    file.stream.seek(0)  # Reset the file pointer after reading
    return mime in ['image/png', 'image/jpeg', 'image/gif']

#check bitstream for virus signatures
#done by alexander
def virus_check(file_bytes):
    try:
        cd = pyclamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)
        result = cd.scan_stream(file_bytes)
        return result
    except:
        cd = pyclamd.ClamdUnixSocket()
        result = cd.scan_stream(file_bytes)
    return result




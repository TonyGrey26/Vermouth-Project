# ClamAV Usage

```python
from clamav_wrapper import ClamavWrapper

result = ClamavWrapper(host='localhost', port=3310).scan_file(<file_path>)
```
Với `<file_path>` có thể là relative path của file hoặc là absolute path của file.

# Result
* Sau khi tiến hành scan file mà không nhận bất kỳ lỗi nào, clamav sẽ trả ra 2 kết quả tương ứng như sau:
  * `OK`: File không chứa virus (file an toàn)
  * `<virus name> FOUND`: File chứa loại virus `<virus_name>`
#include <stdint.h>
//#include <mutex>
//#include <condition_variable>
#include <vector>

struct array64{
  uint64_t value;
  //   std::mutex mutex;
  //std::condition_variable cond;
  uint64_t arr[100];
  std::size_t n;
};

extern "C" {
  struct array64* make_array64(std::size_t n, uint64_t init){
        struct array64 *a = new array64;
	if (n < 100) a->n = n; else a->n = 100;
	for (uint64_t i = 0; i < a->n; i++)
	  a->arr[i] = init;
	
        return a;
    }

  void array64_write(struct array64 *a, uint64_t value, uint64_t index){
    if (index < a->n)
      a->arr[index] = value;
    }

  uint64_t array64_read(struct array64 *a, uint64_t index){
    if (index < a->n)
      return a->arr[index];
    else return 0;
    }
    // void array64_reinit(struct array64 *b, size_t n){
    //     std::unique_lock<std::mutex> lock{b->mutex};
    //     b->n = n;
    // }
}

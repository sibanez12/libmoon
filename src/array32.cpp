#include <stdint.h>
//#include <mutex>
//#include <condition_variable>
#include <vector>

struct array32{
  unsigned int value;
  //   std::mutex mutex;
  //std::condition_variable cond;
  unsigned int arr[100];
  std::size_t n;
};

extern "C" {
  struct array32* make_array32(std::size_t n, unsigned int init){
        struct array32 *a = new array32;
	if (n < 100) a->n = n; else a->n = 100;
	for (unsigned i = 0; i < a->n; i++)
	  a->arr[i] = init;
	
        return a;
    }

  void array32_write(struct array32 *a, unsigned int value, unsigned int index){
    if (index < a->n)
      a->arr[index] = value;
    }

  unsigned int array32_read(struct array32 *a, unsigned int index){
    if (index < a->n)
      return a->arr[index];
    else return 0;
    }
    // void array32_reinit(struct array32 *b, size_t n){
    //     std::unique_lock<std::mutex> lock{b->mutex};
    //     b->n = n;
    // }
}

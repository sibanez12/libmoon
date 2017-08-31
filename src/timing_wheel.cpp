#include <stdint.h>
#include <vector>

struct timing_wheel{
  unsigned int current_slot;
  unsigned int arr[100];
  std::size_t n;

};

extern "C" {
  struct timing_wheel* make_timing_wheel(std::size_t n){
        struct timing_wheel *a = new timing_wheel;
	if (n < 100) a->n = n; else a->n = 100;
	for (unsigned i = 0; i < a->n; i++)
	  a->arr[i] = 0;
	a->current_slot = 0;
        return a;
    }
  unsigned int timing_wheel_remove_and_tick(struct timing_wheel* a) {
    unsigned int value = a->arr[a->current_slot];
    a->arr[a->current_slot] = 0;
    a->current_slot = (a->current_slot + 1)%(a->n);
    return value;
  }

  unsigned int timing_wheel_insert(struct timing_wheel* a, unsigned int value, unsigned int i) {
    unsigned int adjusted = 0;
    if (i >= a->n) return a->n;

    unsigned int tmp = ((a->current_slot + i)%(a->n));
    while (a->arr[tmp] and adjusted < a->n) {
      tmp = (a->current_slot + i)%(a->n);
      adjusted++;
    }

    if (adjusted < a->n) {
      a->arr[tmp] = value;
    }
    return adjusted;
  }

  int timing_wheel_peek(struct timing_wheel* a, unsigned int i) {
    unsigned int tmp = ((a->current_slot + i)%(a->n));
    return a->arr[tmp];
  }
    
}



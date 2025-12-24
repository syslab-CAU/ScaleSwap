import array
import time

N = 500_000_000

STATE = array.array('i', (i % 5 for i in range(N)))

start = time.time()
sum_ = 0
for i in range(0, N, 101):
    sum_ += STATE[i]
end = time.time()

print(f"Sum: {sum_}")
print(f"array 모듈 실행 시간: {end - start:.5f} 초")


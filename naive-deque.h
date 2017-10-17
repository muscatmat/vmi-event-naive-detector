#ifndef CONCURRENT_DEQUE_
#define CONCURRENT_DEQUE_

#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>

template <typename T>
class Deque
{
 public:

  T pop() 
  {
    std::unique_lock<std::mutex> mlock(mutex_);
    while (queue_.empty())
    {
      cond_.wait(mlock);
    }
    auto val = queue_.front();
    queue_.pop_front();
    return val;
  }

  void pop(T& item)
  {
    std::unique_lock<std::mutex> mlock(mutex_);
    while (queue_.empty())
    {
      cond_.wait(mlock);
    }
    item = queue_.front();
    queue_.pop_front();
  }

  void push_back(const T& item)
  {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.push_back(item);
    mlock.unlock();
    cond_.notify_one();
  }

  void push_front(const T& item)
  {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.push_front(item);
    mlock.unlock();
    cond_.notify_one();
  }

  Deque()=default;
  Deque(const Deque&) = delete;            // disable copying
  Deque& operator=(const Deque&) = delete; // disable assignment
  
 private:
  std::deque<T> queue_;
  std::mutex mutex_;
  std::condition_variable cond_;
};

#endif
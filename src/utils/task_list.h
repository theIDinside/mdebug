/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common.h>
#include <utils/thread_pool.h>
#include <utils/worker_task.h>

// std
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <vector>

namespace mdb {

// Ordering policy for task result iteration.
enum class ResultOrderPolicy : u8
{
  // The iteration of results is on a first-completed basis, eagerly consuming available values
  Unordered,
  // The iteration of results maintain the order the jobs were submitted, waiting until the next
  // in line is completed.
  MaintainOrdering

};

template <typename T> class ResultGenerator;
template <typename T> class ResultIterator;
template <typename T> class TaskListImpl;

class TaskList
{
public:
  static constexpr ResultOrderPolicy Unordered = ResultOrderPolicy::Unordered;
  static constexpr ResultOrderPolicy MaintainOrdering = ResultOrderPolicy::MaintainOrdering;

  /**
   * Create a new TaskList with specified result type and ordering policy.
   */
  template <typename T> static std::unique_ptr<TaskListImpl<T>> Create(ResultOrderPolicy ordering) noexcept;
};

// The task class which we use to submit to the global `ThreadPool`
template <typename T> class CallableTaskWithResult : public TaskBase
{
  std::function<T()> mCallable;
  std::optional<T> mResult;
  size_t mIndex;

  TaskListImpl<T> *mGroup;

public:
  explicit CallableTaskWithResult(TaskListImpl<T> *group, size_t index, std::function<T()> callable) noexcept
      : mCallable(std::move(callable)), mIndex(index), mGroup(group)
  {
  }

  void
  Execute() noexcept override
  {
    auto result = mCallable();
    mResult = std::move(result);
    mGroup->TaskDone(this);
  }

  std::optional<T> &&
  GetResult() noexcept
  {
    return std::move(mResult);
  }

  [[nodiscard]] bool
  HasResult() const noexcept
  {
    return mResult.has_value();
  }

  [[nodiscard]] size_t
  Index() const
  {
    return mIndex;
  }
};

template <typename T> struct ResultSlot
{
  size_t index;
  std::optional<T> result;
  bool ready{ false };
};

// The iterators hold a shared reference to the collector, whose responsibility is getting the next value to be
// iterated over. See ResultOrderPolicy for how this works.
template <typename T> class ResultCollector
{
  std::vector<ResultSlot<T>> mSlots;
  std::queue<size_t> mReadyQueue; // For Unordered mode
  std::mutex mReadyQueueMutex;
  std::condition_variable mCondition;
  size_t mTotalTasks;
  size_t mCompletedTasks{ 0 };
  size_t mNextOrderedIndex{ 0 }; // For MaintainOrdering mode
  ResultOrderPolicy mOrdering;

  std::optional<T>
  TakeAnyFirstReady() noexcept
  {
    std::unique_lock lock(mReadyQueueMutex);
    // Wait for any result to be ready
    mCondition.wait(lock, [this] { return !mReadyQueue.empty() || mCompletedTasks == mTotalTasks; });

    if (mReadyQueue.empty()) {
      return std::nullopt; // All done
    }

    size_t index = mReadyQueue.front();
    mReadyQueue.pop();
    return std::move(mSlots[index].result);
  }

  std::optional<T>
  TakeNextOrdered() noexcept
  {
    std::unique_lock lock(mReadyQueueMutex);

    mCondition.wait(lock, [this] {
      return (mNextOrderedIndex < mTotalTasks && mSlots[mNextOrderedIndex].ready) ||
             mCompletedTasks == mTotalTasks;
    });

    if (mNextOrderedIndex >= mTotalTasks) {
      return std::nullopt;
    }

    auto result = std::move(mSlots[mNextOrderedIndex].result);
    mNextOrderedIndex++;
    return result;
  }

public:
  ResultCollector(size_t taskCount, ResultOrderPolicy ordering) noexcept
      : mTotalTasks(taskCount), mOrdering(ordering)
  {
    mSlots.resize(taskCount);
    for (size_t i = 0; i < taskCount; ++i) {
      mSlots[i].index = i;
    }
  }

  void
  StoreResult(size_t index, T &&result) noexcept
  {
    mSlots[index].result = std::move(result);
    mSlots[index].ready = true;
    mCompletedTasks++;
    if (mOrdering == ResultOrderPolicy::Unordered) {
      std::lock_guard lock(mReadyQueueMutex);
      mReadyQueue.push(index);
    }
    mCondition.notify_all();
  }

  // For Unordered: blocks until any result is ready
  // For MaintainOrdering: blocks until the next result in order is ready
  std::optional<T>
  WaitForNext() noexcept
  {
    if (mOrdering == ResultOrderPolicy::Unordered) {
      return TakeAnyFirstReady();
    }

    return TakeNextOrdered();
  }

  [[nodiscard]] bool
  HasMore() const noexcept
  {
    std::lock_guard lock(const_cast<std::mutex &>(mReadyQueueMutex));
    if (mOrdering == ResultOrderPolicy::Unordered) {
      return !mReadyQueue.empty() || mCompletedTasks < mTotalTasks;
    }
    return mNextOrderedIndex < mTotalTasks;
  }

  [[nodiscard]] size_t
  TotalTasks() const noexcept
  {
    return mTotalTasks;
  }
};

// Iterator that blocks waiting for results
template <typename T> class ResultIterator
{
  std::shared_ptr<ResultCollector<T>> mCollector;
  std::optional<T> mCurrentValue;
  bool mIsEnd{ false };

public:
  using value_type = T;
  using reference = const T &;
  using pointer = const T *;
  using difference_type = std::ptrdiff_t;
  using iterator_category = std::input_iterator_tag;

  ResultIterator(std::shared_ptr<ResultCollector<T>> collector, bool isEnd) noexcept
      : mCollector(collector), mIsEnd(isEnd)
  {
    if (!mIsEnd) {
      ++(*this); // Load first result
    }
  }

  reference
  operator*() const noexcept
  {
    return *mCurrentValue;
  }

  pointer
  operator->() const noexcept
  {
    return &(*mCurrentValue);
  }

  ResultIterator &
  operator++() noexcept
  {
    // Block waiting for next result
    mCurrentValue = mCollector->WaitForNext();
    if (!mCurrentValue) {
      mIsEnd = true;
    }
    return *this;
  }

  ResultIterator
  operator++(int) noexcept
  {
    ResultIterator tmp = *this;
    ++(*this);
    return tmp;
  }

  bool
  operator==(const ResultIterator &other) const noexcept
  {
    if (mIsEnd && other.mIsEnd) {
      return true;
    }
    if (mIsEnd != other.mIsEnd) {
      return false;
    }
    return mCollector == other.mCollector;
  }

  bool
  operator!=(const ResultIterator &other) const noexcept
  {
    return !(*this == other);
  }
};

// Generator that provides begin()/end() for range-for loops
template <typename T> class ResultGenerator
{
  // TODO: Add methods so that this can be used in scenarions beyond just for(auto v : Commit()), for instance
  //      one thing we may want is a poll-interface. Right now we always block when doing for(auto v : Commit()),
  //      which is fine for now.
  std::shared_ptr<ResultCollector<T>> mCollector;

public:
  explicit ResultGenerator(std::shared_ptr<ResultCollector<T>> collector) noexcept : mCollector(collector) {}

  ResultIterator<T>
  begin() noexcept
  {
    return ResultIterator<T>(mCollector, false);
  }

  ResultIterator<T>
  end() noexcept
  {
    return ResultIterator<T>(mCollector, true);
  }
};

// Implementation details of the task list
template <typename T> class TaskListImpl
{
  std::vector<std::shared_ptr<TaskBase>> mTasks;
  ResultOrderPolicy mOrdering;
  std::shared_ptr<ResultCollector<T>> mResultCollector{ nullptr };
  bool mCommitted{ false };

public:
  explicit TaskListImpl(ResultOrderPolicy ordering) noexcept : mOrdering(ordering) {}

  /**
   * Add a task to list
   */
  template <typename Callable>
  void
  Add(Callable &&callable) noexcept
  {
    MDB_ASSERT(!mCommitted, "Cannot add tasks after Commit() has been called");
    mTasks.push_back(
      std::make_shared<CallableTaskWithResult<T>>(this, mTasks.size(), std::forward<Callable>(callable)));
  }

  /**
   * Commit the tasks for execution and return a generator for iterating results
   * Results are yielded as they become available (Unordered) or in submission order (MaintainOrdering)
   * @return A ResultGenerator that can be used in range-for loops
   */
  ResultGenerator<T>
  Commit() noexcept
  {
    MDB_ASSERT(!mCommitted, "Commit() can only be called once");
    mCommitted = true;

    if (mTasks.empty()) {
      mResultCollector = std::make_shared<ResultCollector<T>>(0, mOrdering);
      return ResultGenerator<T>(mResultCollector);
    }

    mResultCollector = std::make_shared<ResultCollector<T>>(mTasks.size(), mOrdering);

    ThreadPool::GetGlobalPool()->PostTasks(mTasks);
    return ResultGenerator<T>(mResultCollector);
  }

  void
  TaskDone(CallableTaskWithResult<T> *task) noexcept
  {
    mResultCollector->StoreResult(task->Index(), std::move(*task->GetResult()));
  }
};

// Factory method implementation
template <typename T>
inline std::unique_ptr<TaskListImpl<T>>
TaskList::Create(ResultOrderPolicy ordering) noexcept
{
  return std::make_unique<TaskListImpl<T>>(ordering);
}

} // namespace mdb

/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include "gtest/gtest.h"

#include "list_wrapper.h"

using ::webrtc::ListWrapper;
using ::webrtc::ListItem;

// Note: kNumberOfElements needs to be even.
const unsigned int kNumberOfElements = 10;

// An opaque implementation of dynamic or statically allocated unsigned ints.
// This class makes it possible to use the exact same code for testing of both
// the dynamic and static implementation of ListWrapper.
// Clarification: ListWrapper has two versions of PushBack(..). It takes an
// unsigned integer or a void pointer. The integer implementation takes care
// of memory management. The void pointer version expect the caller to manage
// the memory associated with the void pointer.
// This class works like the integer version but can be implemented on top of
// either the integer version or void pointer version of ListWrapper.
// Note: the non-virtual fuctions behave the same for both versions.
class ListWrapperSimple {
public:
    static ListWrapperSimple* Create(bool static_allocation);
    virtual ~ListWrapperSimple() {}

    // These three functions should be used for manipulating ListItems so that
    // they are the type corresponding to the underlying implementation.
    virtual unsigned int GetUnsignedItem(
        const ListItem* item) const = 0;
    virtual ListItem* CreateListItem(unsigned int item_id) = 0;
    virtual bool DestroyListItem(ListItem* item) = 0;

    unsigned int GetSize() const {
        return list_.GetSize();
    }
    virtual int PushBack(const unsigned int item_id) = 0;
    virtual int PushFront(const unsigned int item_id) = 0;
    virtual int PopFront() = 0;
    virtual int PopBack() = 0;
    bool Empty() const {
        return list_.Empty();
    }
    ListItem* First() const {
        return list_.First();
    }
    ListItem* Last() const {
        return list_.Last();
    }
    ListItem* Next(ListItem* item) const {
        return list_.Next(item);
    }
    ListItem* Previous(ListItem* item) const {
        return list_.Previous(item);
    }
    virtual int Erase(ListItem* item) = 0;
    int Insert(ListItem* existing_previous_item,
                       ListItem* new_item) {
        return list_.Insert(existing_previous_item, new_item);
    }

    int InsertBefore(ListItem* existing_next_item,
                             ListItem* new_item) {
        return list_.InsertBefore(existing_next_item, new_item);
    }
protected:
    ListWrapperSimple() {}

    ListWrapper list_;
};

class ListWrapperStatic : public ListWrapperSimple {
public:
    ListWrapperStatic() {}
    virtual ~ListWrapperStatic() {}

    virtual unsigned int GetUnsignedItem(const ListItem* item) const {
        return item->GetUnsignedItem();
    }
    virtual ListItem* CreateListItem(unsigned int item_id) {
        return new ListItem(item_id);
    }
    virtual bool DestroyListItem(ListItem* item) {
        if (item == NULL) {
            return false;
        }
        delete item;
        return true;
    }
    virtual int PushBack(const unsigned int item_id) {
        return list_.PushBack(item_id);
    }
    virtual int PushFront(const unsigned int item_id) {
        return list_.PushFront(item_id);
    }
    virtual int PopFront() {
        return list_.PopFront();
    }
    virtual int PopBack() {
        return list_.PopBack();
    }
    virtual int Erase(ListItem* item) {
        return list_.Erase(item);
    }
};

class ListWrapperDynamic : public ListWrapperSimple {
public:
    ListWrapperDynamic() {}
    virtual ~ListWrapperDynamic() {}

    virtual unsigned int GetUnsignedItem(const ListItem* item) const {
        const unsigned int* return_value_pointer =
            reinterpret_cast<unsigned int*> (item->GetItem());
        if (return_value_pointer == NULL) {
            return -1;
        }
        return *return_value_pointer;
    }
    virtual ListItem* CreateListItem(unsigned int item_id) {
        unsigned int* item_id_pointer = new unsigned int;
        if (item_id_pointer == NULL) {
            return NULL;
        }
        *item_id_pointer = item_id;
        ListItem* return_value = new ListItem(
            reinterpret_cast<void*>(item_id_pointer));
        if (return_value == NULL) {
            delete item_id_pointer;
            return NULL;
        }
        return return_value;
    }
    virtual bool DestroyListItem(ListItem* item) {
        if (item == NULL) {
            return false;
        }
        bool return_value = false;
        unsigned int* item_id_ptr = reinterpret_cast<unsigned int*>(
            item->GetItem());
        if (item_id_ptr != NULL) {
            return_value = true;
            delete item_id_ptr;
        }
        delete item;
        return return_value;
    }
    virtual int PushBack(const unsigned int item_id) {
        unsigned int* item_id_ptr = new unsigned int;
        if (item_id_ptr == NULL) {
            return -1;
        }
        *item_id_ptr = item_id;
        const int return_value = list_.PushBack(
            reinterpret_cast<void*>(item_id_ptr));
        if (return_value != 0) {
            delete item_id_ptr;
        }
        return return_value;
    }
    virtual int PushFront(const unsigned int item_id) {
        unsigned int* item_id_ptr = new unsigned int;
        if (item_id_ptr == NULL) {
            return -1;
        }
        *item_id_ptr = item_id;
        const int return_value = list_.PushFront(
            reinterpret_cast<void*>(item_id_ptr));
        if (return_value != 0) {
            delete item_id_ptr;
        }
        return return_value;
    }
    virtual int PopFront() {
        return Erase(list_.First());
    }
    virtual int PopBack() {
        return Erase(list_.Last());
    }
    virtual int Erase(ListItem* item) {
        if (item == NULL) {
            return -1;
        }
        unsigned int* item_id_ptr = reinterpret_cast<unsigned int*> (
            item->GetItem());
        int return_value = -1;
        if (item_id_ptr != NULL) {
            delete item_id_ptr;
            return_value = 0;
        }
        if (list_.Erase(item) != 0) {
            return -1;
        }
        return return_value;
    }
};

ListWrapperSimple* ListWrapperSimple::Create(bool static_allocation) {
    if(static_allocation)
    {
        return new ListWrapperStatic();
    }
    return new ListWrapperDynamic();
}

void ClearList(ListWrapperSimple* list) {
    if (list == NULL)
    {
        return;
    }
    while (list->Erase(list->First()) == 0) {
    }
}

ListWrapperSimple* CreateAscendingList(bool static_allocation) {
    ListWrapperSimple* return_value = ListWrapperSimple::Create(
        static_allocation);
    if (return_value == NULL) {
        return NULL;
    }
    for (unsigned int i = 0; i < kNumberOfElements; ++i) {
        if (return_value->PushBack(i) == -1) {
            ClearList(return_value);
            delete return_value;
            return NULL;
        }
    }
    return return_value;
}

ListWrapperSimple* CreateDecendingList(bool static_allocation) {
    ListWrapperSimple* return_value = ListWrapperSimple::Create(
        static_allocation);
    if (return_value == NULL) {
        return NULL;
    }
    for (unsigned int i = 0; i < kNumberOfElements; ++i) {
        if (return_value->PushBack(kNumberOfElements - i - 1) == -1) {
            ClearList(return_value);
            delete return_value;
            return NULL;
        }
    }
    return return_value;
}

// [0,kNumberOfElements - 1,1,kNumberOfElements - 2,...] (this is why
// kNumberOfElements need to be even)
ListWrapperSimple* CreateInterleavedList(bool static_allocation) {
    ListWrapperSimple* return_value = ListWrapperSimple::Create(
        static_allocation);
    if (return_value == NULL) {
        return NULL;
    }
    unsigned int uneven_count = 0;
    unsigned int even_count = 0;
    for (unsigned int i = 0; i < kNumberOfElements; i++) {
        unsigned int push_value = 0;
        if ((i % 2) == 0) {
            push_value = even_count;
            even_count++;
        } else {
            push_value = kNumberOfElements - uneven_count - 1;
            uneven_count++;
        }
        if (return_value->PushBack(push_value) == -1) {
            ClearList(return_value);
            delete return_value;
            return NULL;
        }
    }
    return return_value;
}

void PrintList(const ListWrapperSimple* list) {
    ListItem* list_item = list->First();
    printf("[");
    while (list_item != NULL)
    {
        printf("%3u", list->GetUnsignedItem(list_item));
        list_item = list->Next(list_item);
    }
    printf("]\n");
}

bool CompareLists(const ListWrapperSimple* lhs, const ListWrapperSimple* rhs) {
    const unsigned int list_size = lhs->GetSize();
    if (lhs->GetSize() != rhs->GetSize()) {
        return false;
    }
    if (lhs->Empty()) {
        return rhs->Empty();
    }
    unsigned int i = 0;
    ListItem* lhs_item = lhs->First();
    ListItem* rhs_item = rhs->First();
    while (i < list_size) {
        if (lhs_item == NULL) {
            return false;
        }
        if (rhs_item == NULL) {
            return false;
        }
        if (lhs->GetUnsignedItem(lhs_item) != rhs->GetUnsignedItem(rhs_item)) {
            return false;
        }
        i++;
        lhs_item = lhs->Next(lhs_item);
        rhs_item = rhs->Next(rhs_item);
    }
    return true;
}

TEST(ListWrapperTest,ReverseNewIntList) {
    // Create a new temporary list with elements reversed those of
    // new_int_list_
    const ListWrapperSimple* decending_list = CreateDecendingList(rand()%2);
    ASSERT_FALSE(decending_list == NULL);
    ASSERT_FALSE(decending_list->Empty());
    ASSERT_EQ(kNumberOfElements,decending_list->GetSize());

    const ListWrapperSimple* ascending_list = CreateAscendingList(rand()%2);
    ASSERT_FALSE(ascending_list == NULL);
    ASSERT_FALSE(ascending_list->Empty());
    ASSERT_EQ(kNumberOfElements,ascending_list->GetSize());

    ListWrapperSimple* list_to_reverse = ListWrapperSimple::Create(rand()%2);

    // Reverse the list using PushBack and Previous.
    for (ListItem* item = ascending_list->Last(); item != NULL;
         item = ascending_list->Previous(item)) {
         list_to_reverse->PushBack(ascending_list->GetUnsignedItem(item));
    }

    ASSERT_TRUE(CompareLists(decending_list,list_to_reverse));

    ListWrapperSimple* list_to_un_reverse =
        ListWrapperSimple::Create(rand()%2);
    ASSERT_FALSE(list_to_un_reverse == NULL);
    // Reverse the reversed list using PushFront and Next.
    for (ListItem* item = list_to_reverse->First(); item != NULL;
         item = list_to_reverse->Next(item)) {
         list_to_un_reverse->PushFront(list_to_reverse->GetUnsignedItem(item));
    }

    ASSERT_TRUE(CompareLists(ascending_list,list_to_un_reverse));
}

TEST(ListWrapperTest,PopTest) {
    ListWrapperSimple* ascending_list = CreateAscendingList(rand()%2);
    ASSERT_FALSE(ascending_list == NULL);
    ASSERT_FALSE(ascending_list->Empty());
    EXPECT_EQ(0,ascending_list->PopFront());
    EXPECT_EQ(1,ascending_list->GetUnsignedItem(ascending_list->First()));

    EXPECT_EQ(0,ascending_list->PopBack());
    EXPECT_EQ(kNumberOfElements - 2,ascending_list->GetUnsignedItem(
              ascending_list->Last()));
    EXPECT_EQ(kNumberOfElements - 2, ascending_list->GetSize());
}

// Use Insert to interleave two lists.
TEST(ListWrapperTest,InterLeaveTest) {
    ListWrapperSimple* interleave_list = CreateAscendingList(rand()%2);
    ASSERT_FALSE(interleave_list == NULL);
    ASSERT_FALSE(interleave_list->Empty());

    ListWrapperSimple* decending_list = CreateDecendingList(rand()%2);
    ASSERT_FALSE(decending_list == NULL);

    for (int i = 0; i < kNumberOfElements/2; ++i) {
        ASSERT_EQ(0,interleave_list->PopBack());
        ASSERT_EQ(0,decending_list->PopBack());
    }
    ASSERT_EQ(kNumberOfElements/2,interleave_list->GetSize());
    ASSERT_EQ(kNumberOfElements/2,decending_list->GetSize());

    int insert_position = kNumberOfElements/2;
    ASSERT_EQ(insert_position * 2, kNumberOfElements);
    while (!decending_list->Empty())
    {
        ListItem* item = decending_list->Last();
        ASSERT_FALSE(item == NULL);

        const unsigned int item_id = decending_list->GetUnsignedItem(item);
        ASSERT_EQ(0,decending_list->Erase(item));

        ListItem* insert_item = interleave_list->CreateListItem(item_id);
        ASSERT_FALSE(insert_item == NULL);
        item = interleave_list->First();
        ASSERT_FALSE(item == NULL);
        for (int j = 0; j < insert_position - 1; ++j) {
            item = interleave_list->Next(item);
            ASSERT_FALSE(item == NULL);
        }
        if (0 != interleave_list->Insert(item,insert_item)) {
            interleave_list->DestroyListItem(insert_item);
            FAIL();
        }
        --insert_position;
    }

    ListWrapperSimple* interleaved_list = CreateInterleavedList(rand()%2);
    ASSERT_FALSE(interleaved_list == NULL);
    ASSERT_FALSE(interleaved_list->Empty());

    ASSERT_TRUE(CompareLists(interleaved_list,interleave_list));
}

// Use InsertBefore to interleave two lists.
TEST(ListWrapperTest,InterLeaveTestII) {
    ListWrapperSimple* interleave_list = CreateDecendingList(rand()%2);
    ASSERT_FALSE(interleave_list == NULL);
    ASSERT_FALSE(interleave_list->Empty());

    ListWrapperSimple* ascending_list = CreateAscendingList(rand()%2);
    ASSERT_FALSE(ascending_list == NULL);

    for (int i = 0; i < kNumberOfElements/2; ++i) {
        ASSERT_EQ(0,interleave_list->PopBack());
        ASSERT_EQ(0,ascending_list->PopBack());
    }
    ASSERT_EQ(kNumberOfElements/2,interleave_list->GetSize());
    ASSERT_EQ(kNumberOfElements/2,ascending_list->GetSize());

    int insert_position = kNumberOfElements/2;
    ASSERT_EQ(insert_position * 2, kNumberOfElements);
    while (!ascending_list->Empty())
    {
        ListItem* item = ascending_list->Last();
        ASSERT_FALSE(item == NULL);

        const unsigned int item_id = ascending_list->GetUnsignedItem(item);
        ASSERT_EQ(0,ascending_list->Erase(item));

        ListItem* insert_item = interleave_list->CreateListItem(item_id);
        ASSERT_FALSE(insert_item == NULL);
        item = interleave_list->First();
        ASSERT_FALSE(item == NULL);
        for (int j = 0; j < insert_position - 1; ++j) {
            item = interleave_list->Next(item);
            ASSERT_FALSE(item == NULL);
        }
        if (0 != interleave_list->InsertBefore(item,insert_item)) {
            interleave_list->DestroyListItem(insert_item);
            FAIL();
        }
        --insert_position;
    }

    ListWrapperSimple* interleaved_list = CreateInterleavedList(rand()%2);
    ASSERT_FALSE(interleaved_list == NULL);
    ASSERT_FALSE(interleaved_list->Empty());

    ASSERT_TRUE(CompareLists(interleaved_list,interleave_list));
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    // Added return_value so that it's convenient to put a breakpoint before
    // exiting please note that the return value from RUN_ALL_TESTS() must
    // be returned by the main function.
    const int return_value = RUN_ALL_TESTS();
    return return_value;
}

from sipsimple.applications.test import XMLApplicationTest
from sipsimple.applications.resourcelists import DisplayName, Entry, EntryRef, External, List, ResourceLists


example_from_section_3_3_rfc = """<?xml version="1.0" encoding="UTF-8"?>
<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <list name="friends">
  <entry uri="sip:bill@example.com">
   <display-name>Bill Doe</display-name>
  </entry>
  <entry-ref ref="resource-lists/users..."/>
  <list name="close-friends">
   <display-name>Close Friends</display-name>
   <entry uri="sip:joe@example.com">
    <display-name>Joe Smith</display-name>
   </entry>
   <entry uri="sip:nancy@example.com">
    <display-name>Nancy Gross</display-name>
   </entry>
   <external anchor="http://xcap.example.org/resource-lists...">
    <display-name>Marketing</display-name>
   </external>
  </list>
 </list>
</resource-lists>"""


class ResourceListsTest(XMLApplicationTest):
    _test_module = 'resourcelists'

    def test_list_type_checking(self):
        self.assertRaises(TypeError, List, ['2'])

    def test_list_constraint(self):
        lst = List([Entry('sip:alice@example.com')])
        self.assertRaises(ValueError, lst.append, Entry('sip:alice@example.com', display_name='Alice'))

    def test_display_name(self):
        self.assertEqual(DisplayName('123'), DisplayName ('123'))
        self.assertNotEqual(DisplayName('123'), DisplayName ('123', lang = 'en'))

    def test_resouce_lists(self):
        bill = Entry('sip:bill@example.com', display_name = 'Bill Doe')
        ref = EntryRef('a/b/c', display_name = u'Unicode')
        ext = External('http://localhost')
        lst = List([bill, ref, ext, List(name='inside')], display_name = 'mylist')
        rl = ResourceLists()
        rl.append(lst)

        rl2 = ResourceLists.parse(rl.toxml())
        self.assertEqual(len(rl2), len(rl))
        lst2 = rl2[0]
        self.assertEqual(len(lst2), len(lst))
        self.assertEqual(lst2.display_name, lst.display_name)
        bill2 = lst2[0]
        ref2 = lst2[1]
        ext2 = lst2[2]
        self.assertEqual(lst2[3].name, 'inside')
        self.assertEqual(bill2, bill)
        self.assertEqual(ref2, ref)
        self.assertEqual(ext2, ext)

        bill2.display_name = 'New Bill'
        assert bill2 != bill


if __name__ == '__main__':
    ResourceListsTest.execute()

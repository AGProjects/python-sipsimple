from pypjua.applications.test import XMLApplicationTest
from pypjua.applications.rlsservices import Package, Packages, ResourceList, RLSList, Service, RLSServices
from pypjua.applications.resourcelists import DisplayName, Entry, EntryRef, External, List, ResourceLists


example_from_section_4_3_rfc = """<?xml version="1.0" encoding="UTF-8"?>
<rls-services xmlns="urn:ietf:params:xml:ns:rls-services"
   xmlns:rl="urn:ietf:params:xml:ns:resource-lists"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <service uri="sip:mybuddies@example.com">
  <resource-list>http://xcap.example.com/xxx</resource-list>
  <packages>
   <package>presence</package>
  </packages>
 </service>
 <service uri="sip:marketing@example.com">
   <list name="marketing">
     <rl:entry uri="sip:joe@example.com"/>
     <rl:entry uri="sip:sudhir@example.com"/>
   </list>
   <packages>
     <package>presence</package>
   </packages>
 </service>
</rls-services>"""


class RLSServicesTest(XMLApplicationTest):
    _test_module = 'rlsservices'

    def test_rls_services(self):
        packages = Packages(['presence'])
        self.assertEqual(packages[0], Package('presence'))

        service = Service(uri='alicebuddies@example.com', list='http://xcap.example.com/xcap-root/resource-lists/users/alice/index.xml')
        self.assertEqual(len(service.packages), 0)
        service.packages = packages

        rls = RLSServices()
        self.assertEqual(len(rls), 0)
        rls.append(service)

        service2 = Service(uri='mybuddies@example.com', list=RLSList([Entry('sip:bob@example.com', display_name='Bob')]))
        service2.list.append(List())
        
        rls.append(service2)

        rls2 = RLSServices.parse(rls.toxml())
        self.assertEqual(len(rls2), 2)
        self.assertEqual(len(rls2[1].list[1]), 0)
        self.assertEqual(rls2[1].list[0], Entry('sip:bob@example.com', display_name='Bob'))



if __name__ == '__main__':
    RLSServicesTest.execute()

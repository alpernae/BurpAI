from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # Assign callbacks to self._callbacks here:
        self._callbacks = callbacks 
        self._helpers = callbacks.getHelpers()
        # Now you can use self._callbacks:
        self._callbacks.setExtensionName("Print Request & Response")
        self._callbacks.registerContextMenuFactory(self)
        print("[+] Print Request & Response extension loaded.")
        

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuList.add(JMenuItem("Send Request > Print Request & Response", actionPerformed=self.printRequestResponse))
        return menuList

    def printRequestResponse(self, event):
        # Get the selected message
        selectedMessages = self.context.getSelectedMessages()
        if len(selectedMessages) != 1:
            print("[-] Please select a single request or response.")
            return

        message = selectedMessages[0]
        msgInfo = self._helpers.analyzeRequest(message)
        
        # Extract request information
        request = message.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)
        requestHeaders = analyzedRequest.getHeaders()
        requestBody = request[analyzedRequest.getBodyOffset():].tostring()
        
        # Extract response information
        response = message.getResponse()
        if response:  # Check if response exists
            analyzedResponse = self._helpers.analyzeResponse(response)
            responseHeaders = analyzedResponse.getHeaders()
            responseBody = response[analyzedResponse.getBodyOffset():].tostring()
        else:
            responseHeaders = ["No response found."]
            responseBody = ""

        # Format and print request
        print("-" * 50 + "\nREQUEST:\n" + "-" * 50)
        print("\n".join(requestHeaders))
        print(requestBody)

        # Format and print response
        print("-" * 50 + "\nRESPONSE:\n" + "-" * 50)
        print("\n".join(responseHeaders))
        print(responseBody)
legitimate = 1
suspicious = 0
phishy = -1 

legitimateIndex = 0
suspiciousIndex = 1
phishyIndex = 2

attributePossibleValues = 3

def readData():
    with open ("PhishingData.txt", "r") as f:
        data = f.readlines() # read raw lines into an array
    return data

def createMatrix(data):
    #create matrix out of data
    data_matrix = [] 
    for raw_line in data:
        split_line = raw_line.strip().split(",")
        nums_ls = [int(x.replace('"', '')) for x in split_line]
        data_matrix.append(nums_ls)    
    return data_matrix

def createVerticalRepresentation(validationSet, attributeCount):        
    validationRep = []    
    for attrInd in range(attributeCount):
        attribute = ([], [], [])        
        i = 0
        for s in validationSet:
            attrValue = s[attrInd]
            if attrValue == legitimate:
                attribute[legitimateIndex].append(i)
            if attrValue == suspicious:
                attribute[suspiciousIndex].append(i)
            if attrValue == phishy:
                attribute[phishyIndex].append(i)
            i += 1
        validationRep.append(attribute)
    return validationRep


def getLabel(validationSet, index):
    labelIndex = 9
    label = validationSet[index][labelIndex]
    return label

def pruner(support, confidence):
    #minimum support percentage (amount of times association occured / all instances)
    minsupp = 0.02
    #minumum confidence percentage (amount of times association rule -> x class / amount of times association rule occured)
    minconf = 0.40
    return support >= minsupp and confidence >= minconf

#The criteria order is: rule’s confidence, support, length and class frequency.
def createRule(attributeIndex, attributes, label, confidence, support, frequency, length):
    rule = [attributeIndex, attributes, label, support, confidence, frequency, length]
    return rule

#good luck
def ruleDiscovery(validationSet, validationRep):
    legitimateIndexes = []
    suspiciousIndexes = []
    phishyIndexes = []
    labelIndex = 9
    validationSetSize = len(validationSet)
    
    for i, item in enumerate(validationSet):
        label = getLabel(validationSet, i)
        if label == legitimate:
            legitimateIndexes.append(i)
        if label == suspicious:
            suspiciousIndexes.append(i)
        if label == phishy:
            phishyIndexes.append(i)
    
    ruleList = []
    associationList = []
    associationAttributeIndex = 0
    associationAttributeValueIndex = 1
    associationTidsIndex = 2
    
    #attrIdx is the index of the corresponding attribute (A, B, C, D)
    #idx is which index of the value (A1, B2, B3)
    for attrIdx, attr in enumerate(validationRep):
        for idx in range (attributePossibleValues):
            specificAttributeTIDs = attr[idx]
            totalTimesAttributeSeen = len(specificAttributeTIDs)                                        
            if totalTimesAttributeSeen > 0:
                #here is where we start looking for multi-attribute associations
                tempAssociationList = []
                for association in associationList:
                    #this could get a little hairy....
                    attributeIdxList = association[associationAttributeIndex]
                    attributeValIdxList = association[associationAttributeValueIndex]
                    tids = association[associationTidsIndex]
                    sharedTids = list(set(tids).intersection(specificAttributeTIDs))
                    sharedTidsSize = len(sharedTids)
                    if sharedTidsSize > 0:
                        newAssociationIdxList = attributeIdxList + [attrIdx]
                        newAssociationIdxValList = attributeValIdxList + [idx]
                        assoc = [newAssociationIdxList, newAssociationIdxValList, sharedTids]
                        tempAssociationList.append(assoc)    
                        
                if len(tempAssociationList) > 0:
                    associationList = associationList + tempAssociationList
                association = [[attrIdx], [idx], specificAttributeTIDs]
                associationList.append(association)
                
    for association in associationList:
        associationAttrIdx = association[associationAttributeIndex]
        associationIdx = association[associationAttributeValueIndex]
        associationTIDs = association[associationTidsIndex]
        totalTIDs = len(associationTIDs)
        tidsC1 = list(set(associationTIDs).intersection(legitimateIndexes))
        frequencyC1 = len(tidsC1)
        tidsC2 = list(set(associationTIDs).intersection(suspiciousIndexes))
        frequencyC2 = len(tidsC2)
        tidsC3 = list(set(associationTIDs).intersection(phishyIndexes))
        frequencyC3 = len(tidsC3)
    
        confidenceC1 = float(frequencyC1 / totalTIDs)
        confidenceC2 = float(frequencyC2 / totalTIDs)
        confidenceC3 = float(frequencyC3 / totalTIDs)
    
        supportC1 = float(frequencyC1 / validationSetSize)
        supportC2 = float(frequencyC2 / validationSetSize)
        supportC3 = float(frequencyC3 / validationSetSize)
        
        decisionC1 = pruner(supportC1, confidenceC1)
        decisionC2 = pruner(supportC2, confidenceC2)
        decisionC3 = pruner(supportC3, confidenceC3)        
        
        if decisionC1:
            length = len(tidsC1)
            genRule = createRule(associationAttrIdx, associationIdx, legitimate, confidenceC1, supportC1, frequencyC1, length)
            ruleList.append(genRule)
        if decisionC2:
            length = len(tidsC2)
            genRule = createRule(associationAttrIdx, associationIdx, suspicious, confidenceC2, supportC2, frequencyC2, length)
            ruleList.append(genRule)
        if decisionC3:
            length = len(tidsC3)
            genRule = createRule(associationAttrIdx, associationIdx, phishy, confidenceC3, supportC3, frequencyC3, length)
            ruleList.append(genRule)        
            
    return ruleList
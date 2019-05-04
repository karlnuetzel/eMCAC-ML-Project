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
    associationClassIndex = 2
    associationTidsIndex = 3
    
    #attrIdx is the index of the corresponding attribute (A, B, C, D)
    #idx is which index of the value (A1, B2, B3)
    for attrIdx, attr in enumerate(validationRep):
        for idx in range (attributePossibleValues):
            specificAttributeTIDs = attr[idx]
            totalTimesAttributeSeen = len(specificAttributeTIDs)    
                                                
            if totalTimesAttributeSeen > 0:
                tidsC1 = list(set(specificAttributeTIDs).intersection(legitimateIndexes))
                frequencyC1 = len(tidsC1)
                tidsC2 = list(set(specificAttributeTIDs).intersection(suspiciousIndexes))
                frequencyC2 = len(tidsC2)
                tidsC3 = list(set(specificAttributeTIDs).intersection(phishyIndexes))
                frequencyC3 = len(tidsC3)
                
                confidenceC1 = float(frequencyC1 / totalTimesAttributeSeen)
                confidenceC2 = float(frequencyC2 / totalTimesAttributeSeen)
                confidenceC3 = float(frequencyC3 / totalTimesAttributeSeen)
                
                supportC1 = float(frequencyC1 / validationSetSize)
                supportC2 = float(frequencyC2 / validationSetSize)
                supportC3 = float(frequencyC3 / validationSetSize)
                
                #here is where we start looking for multi-attribute associations
                tempAssociationList = []
                for association in associationList:
                    #this could get a little hairy....
                    classID = association[associationClassIndex]
                    attributeIdxList = association[associationAttributeIndex]
                    attributeValIdxList = association[associationAttributeValueIndex]
                    tids = association[associationTidsIndex]
                    
                    frequency = 0
                    if classID == legitimate:
                        frequency = frequencyC1
                        newTids = tidsC1
                    if classID == suspicious:
                        frequency = frequencyC2
                        newTids = tidsC2
                    if classID == phishy:
                        frequency = frequencyC3
                        newTids = tidsC3
                    if frequency > 0:
                        sharedTids = list(set(tids).intersection(newTids))
                        support = len(tidsC1) + len(tidsC2) + len(tidsC3)
                        frequencyOfNewAssociation = 0
                        bigBoyTids = []
                        for tid in sharedTids:
                            data = validationSet[tid]
                            if data[labelIndex] == classID:
                                bigBoyTids.append(tid)
                                frequencyOfNewAssociation += 1
                        if frequencyOfNewAssociation > 0:
                            newAssociationIdxList = attributeIdxList + [attrIdx]
                            newAssociationIdxValList = attributeValIdxList + [idx]
                            newAssociationTidsList = bigBoyTids
                            assoc = [newAssociationIdxList, newAssociationIdxValList, classID, bigBoyTids]
                            tempAssociationList.append(assoc)                                
                            
                            conf = float(frequencyOfNewAssociation / support)
                            supp = float(frequencyOfNewAssociation / validationSetSize)
                            decision = pruner(supp, conf)
                            if decision:
                                length = len(bigBoyTids)
                                genRule = createRule(newAssociationIdxList, newAssociationIdxValList, classID, conf, supp, frequencyOfNewAssociation, length)
                                ruleList.append(genRule)
                                
                if len(tempAssociationList) > 0:
                    associationList = associationList + tempAssociationList
                if frequencyC1 > 0:
                    association = [[attrIdx], [idx], legitimate, tidsC1]
                    associationList.append(association)
                if frequencyC2:
                    association = [[attrIdx], [idx], suspicious, tidsC2]
                    associationList.append(association)
                if frequencyC3:
                    association = [[attrIdx], [idx], phishy, tidsC3]
                    associationList.append(association)
                decisionC1 = pruner(supportC1, confidenceC1)
                decisionC2 = pruner(supportC2, confidenceC2)
                decisionC3 = pruner(supportC3, confidenceC3)
                
                if decisionC1:
                    length = len(tidsC1)
                    genRule = createRule([attrIdx], [idx], legitimate, confidenceC1, supportC1, frequencyC1, length)
                    ruleList.append(genRule)
                if decisionC2:
                    length = len(tidsC2)
                    genRule = createRule([attrIdx], [idx], suspicious, confidenceC2, supportC2, frequencyC2, length)
                    ruleList.append(genRule)
                if decisionC3:
                    length = len(tidsC3)
                    genRule = createRule([attrIdx], [idx], phishy, confidenceC3, supportC3, frequencyC3, length)
                    ruleList.append(genRule)
    return ruleList
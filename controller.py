from rulediscovery import *
import operator
#eMCAC reference
#https://www.sciencedirect.com/science/article/pii/S2210832714000210
#Data Source
#http://archive.ics.uci.edu/ml/datasets/Website+Phishing
legitimate = 1
suspicious = 0
phishy = -1 

legitimateIndex = 0
suspiciousIndex = 1
phishyIndex = 2

def classifier(testData, rules):
    correspondingVal = [1, 0, -1]
    attributeIndex = 0
    attributeValIndex = 1
    classIDIndex = 2
    decisionClass = None
    for rule in rules:
        #finding first matching rule
        attributes = rule[attributeIndex]
        amountOfAttributesInRule = len(attributes)
        attributeVals = rule[attributeValIndex]
        classID = rule[classIDIndex]
        for i, attr in enumerate(attributes):
            index = attributeVals[i]
            #does the test attribute correspond to the rule attribute
            if testData[attr] == correspondingVal[index]:
                #continue....
                #lets check if we passed every attribute rule
                if amountOfAttributesInRule == (i+1):
                    #it matches the rule completely --> classify
                    return classID
            else:
                #it doesnt correspond so this rule isnt valid (SKIP!)
                break
    return 0      

def mcac():
    data = readData()
    data_matrix = createMatrix(data)
    
    labelIndex = 9
    attributeCount = 9    
    
    #548 legitimate websites out of 1353 websites. There is 702 phishing URLs, and 103 suspicious URLs. 
    legitimate_matrix = [item for item in data_matrix if item[labelIndex] == 1]
    suspicious_matrix = [item for item in data_matrix if item[labelIndex] == 0]
    phishy_matrix = [item for item in data_matrix if item[labelIndex] == -1]

    
    #1353 websites....
    #548 legitimate ... 548 / 2 => 274
    #103 suspicious ... 103 / 2 => (51, 52)
    #702 phishig ... 702 / 2 => 351
    splitLegitimateSize = 274  #274
    splitSuspiciousSize = 52   #52
    splitPhishingSize = 351    #351
    
    validationSet = legitimate_matrix[0:splitLegitimateSize] + suspicious_matrix[0:splitSuspiciousSize] + phishy_matrix[0:splitPhishingSize]
    testingSet = legitimate_matrix[splitLegitimateSize:] + suspicious_matrix[splitSuspiciousSize:] + phishy_matrix[splitPhishingSize:]

    #for dat in validationSet:
        #print(dat)    
    
    validationRep = createVerticalRepresentation(validationSet, attributeCount)
    rules = ruleDiscovery(validationSet, validationRep)
   
    confidenceIndex = 4
    suportIndex = 3
    lengthIndex = 6
    frequencyIndex = 5
    
    rules = sorted(rules, key = operator.itemgetter(confidenceIndex, suportIndex, lengthIndex, frequencyIndex), reverse=True)
    #rules.sort(key=lambda x: float(x[confidenceIndex]), reverse=True)
    for r in rules:
        print(r[2])
    print(len(rules))
    
    legitimateCount = 0
    suspiciousCount = 0
    phishyCount = 0    
    for test in testingSet:
        if test[labelIndex] == legitimate:
            legitimateCount += 1
        if test[labelIndex] == suspicious:
            suspiciousCount += 1
        if test[labelIndex] == phishy:
            phishyCount += 1
            
    decisionLegitimateCount = 0
    decisionSuspiciousCount = 0
    decisionPhishyCount = 0
    
    for test in testingSet:
        #realLabel = test[labelIndex]
        decision = classifier(test, rules)
        if decision == legitimate:
            decisionLegitimateCount += 1
        if decision == suspicious:
            decisionSuspiciousCount += 1
        if decision == phishy:
            decisionPhishyCount += 1
    print("--- REAL COUNTS ---")
    print("Legit:")
    print(legitimateCount)
    print("Suspicious:")
    print(suspiciousCount)
    print("Phishing:")
    print(phishyCount)
    print("--- DECISION COUNTS ---")
    print("Legit:")
    print(decisionLegitimateCount)
    print("Suspicious:")
    print(decisionSuspiciousCount)
    print("Phishing:")
    print(decisionPhishyCount)
    
mcac()

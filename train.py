from sklearn.cluster import KMeans
import numpy as np
import pandas as pd
from scipy.spatial.distance import cdist
import matplotlib.pyplot as plt

banList = ['1st', '2nd', '3rd', '4th', '5th', '6th', '7th', '8th', '9th', 'of', 'a', 'in', 'or', 'from', 'and', 'with', 'into', 'on', 'by']

with open('result.csv', 'r') as f:
    data = pd.read_csv(f, index_col = 0)
    km = KMeans(n_clusters = 11)
    km.fit(data)
    
    r = open('kmeans.csv', 'w', newline = '')

    # distortions = []
    # K = range(1, 40)
    # for k in K:
    #     model = KMeans(n_clusters = k).fit(data)
    #     distortions.append(sum(np.min(cdist(data, model.cluster_centers_, 'euclidean'), axis = 1)) / data.shape[0])

    # plt.plot(K, distortions, 'bx-')
    # plt.xlabel('k')
    # plt.ylabel('Distortion')
    # plt.title('The Elbow Method showing the optimal k')
    # plt.show()

    result = {}
    for i in range(11):
        result[i] = []

    for i in range(len(data)):
        result[km.labels_[i]].append(data.axes[0][i])

    for label in result:
        groups = {}
        tagGroups = {}
        groupNum = 0

        for name in result[label]:
            foundGroup = -1
            deleteList = []
            tags = name.split('-')

            for tag in tags:
                if tag.isdigit() or tag in banList:
                    deleteList.append(tag)
            
            for d in deleteList:
                tags.remove(d)
            
            for tagGroup in tagGroups:
                if not set(tags).isdisjoint(tagGroups[tagGroup]):
                    foundGroup = tagGroup
                    break
                
            if foundGroup >= 0:
                groups[foundGroup].append(name)
                for tag in tags:
                    if tag not in tagGroups[foundGroup]:
                        tagGroups[foundGroup].append(tag)

            else:
                groups[groupNum] = [name]
                tagGroups[groupNum] = tags
                groupNum += 1

        maxLen = 0
        maxGroup = 0

        for g in groups:
            gLen = len(groups[g])
            
            if maxLen < gLen:
                maxLen = gLen
                maxGroup = g
        
        print(str(100 * maxLen / len(result[label])) + '%')

        for j in (groups[maxGroup]):
            r.write(',' + str(j))
        
        r.write('\n')

    r.close()

    # with open('kmeans.csv', 'w', newline = '') as r:
    #     for i in range(len(result)):
    #         r.write(str(i))

    #         for j in (result[i]):
    #             r.write(',' + str(j))
            
    #         r.write('\n')

    
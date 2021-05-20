import os
import math

if __name__ == "__main__":
    # data_dir = "./wasmi_data/"
    # list = os.listdir(data_dir)
    # for data_file in list:
    #     data_path = data_dir + data_file
    #     with open(data_path, "r") as f:
    #         data_list = f.readlines()
    #         print(data_list)
    #     break

    file1 = "./wasmi_data/data1.txt"
    file2 = "./WaTEE_data/data1.txt"

    result = []

    with open(file1, "r") as f:
        data_list = f.readlines()
        for data in data_list:
            tmp = data.strip().split(": ")
            tmp[1] = math.log(int(tmp[1])/1000)
            result.append(tmp)
    print(result)

    with open(file2, "r") as f:
        data_list = f.readlines()
        for i, data in enumerate(data_list):
            tmp = data.strip().split(": ")
            result[i].append(math.log(int(tmp[1])/1000))
    print(result)
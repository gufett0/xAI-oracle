import torch
import torch.nn as nn
import torch.nn.functional as F

# Define the Siamese neural network

class FurtherAdjustedSiameseBambooNN(nn.Module):
    def __init__(self):
        super(FurtherAdjustedSiameseBambooNN, self).__init__()
        self.embedding_net = nn.Sequential(
            nn.Conv2d(1, 8, kernel_size=3),  # Reduce filters in the first Conv2d layer
            nn.BatchNorm2d(8),
            nn.ReLU(),
            nn.Flatten()
        )
        # Calculate the size of the fully connected layer input based on the spatial dimensions
        self.fc_input_size = self.get_fc_input_size((1, 10, 10))
        self.fc = nn.Sequential(
            nn.Linear(self.fc_input_size, 128),  # Reduce units in the first Linear layer
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 32)  # Reduce units in the second Linear layer
        )
        self.out = nn.Linear(32, 1)  # Output 1 for similar, 0 for dissimilar

    def forward_one(self, x):
        x = x.view(-1, 1, 10, 10)  # Reshape input for convolutional layer
        return self.embedding_net(x)

    def forward(self, x1, x2):
        output1 = self.forward_one(x1)
        output2 = self.forward_one(x2)
        distance = torch.abs(output1 - output2)
        embedded = self.fc(distance)
        output = self.out(embedded)
        return output

    def get_fc_input_size(self, shape):
        with torch.no_grad():
            x = torch.zeros(1, *shape)
            x = self.embedding_net(x)
            return x.view(1, -1).size(1)
        
'''

class FurtherAdjustedSiameseBambooNN(nn.Module):
    def __init__(self):
        super(FurtherAdjustedSiameseBambooNN, self).__init__()
        self.embedding_net = nn.Sequential(
            nn.Conv2d(1, 8, kernel_size=3, padding=1),  # First conv layer
            nn.BatchNorm2d(8),
            nn.ReLU(),
            nn.MaxPool2d(2, 2),  
            nn.Conv2d(8, 16, kernel_size=3, padding=1),  # Second conv layer
            nn.BatchNorm2d(16),
            nn.ReLU(),
            nn.MaxPool2d(2, 2),  
            nn.Conv2d(16, 32, kernel_size=3, padding=1),  # Third conv layer
            nn.BatchNorm2d(32),
            nn.ReLU(),
            nn.MaxPool2d(2, 2), 
            nn.Conv2d(32, 64, kernel_size=3, padding=1),  # Fourth conv layer
            nn.BatchNorm2d(64),
            nn.ReLU(),
            nn.MaxPool2d(2, 2),  
            nn.Conv2d(64, 128, kernel_size=3, padding=1),  # Fifth conv layer
            nn.BatchNorm2d(128),
            nn.ReLU(),
            nn.MaxPool2d(2, 2), 
            nn.Flatten()
        )
        # Calculate the size of the fully connected layer input based on the spatial dimensions
        self.fc_input_size = self.get_fc_input_size((1, 112, 112))
        self.fc = nn.Sequential(
            nn.Linear(self.fc_input_size, 64),  # Reduce units in the first Linear layer
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 16)  # Reduce units in the second Linear layer
        )
        self.out = nn.Linear(16, 1)  # Output 1 for similar, 0 for dissimilar

    def forward_one(self, x):
        x = x.view(-1, 1, 112, 112)  # Reshape input for convolutional layer
        return self.embedding_net(x)

    def forward(self, x1, x2):
        output1 = self.forward_one(x1)
        output2 = self.forward_one(x2)
        distance = torch.abs(output1 - output2)
        embedded = self.fc(distance)
        output = self.out(embedded)
        return output

    def get_fc_input_size(self, shape):
        with torch.no_grad():
            x = torch.zeros(1, *shape)
            x = self.embedding_net(x)
            return x.view(1, -1).size(1)
'''        


'''class SimpleConvNet(nn.Module):
    def __init__(self):
        super(SimpleConvNet, self).__init__()
        self.conv1 = nn.Conv2d(in_channels=1, out_channels=3, kernel_size=3)
        self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)
        
        self.conv2 = nn.Conv2d(in_channels=3, out_channels=6, kernel_size=3)
        self.pool2 = nn.MaxPool2d(kernel_size=2, stride=2)
        self.conv3 = nn.Conv2d(in_channels=6, out_channels=12, kernel_size=3)
        self.pool3 = nn.MaxPool2d(kernel_size=2, stride=2)
        
        self.flattened_size = 12 * 4 * 4  # Adjusted for 50x50 input size reduced by pooling layers
        self.fc1 = nn.Linear(self.flattened_size, 1)
        
        self.dropout = nn.Dropout(p=0.5)

    def forward(self, x1, x2):
        x1 = self.pool1(self.conv1(x1))
        x1 = self.pool2(self.conv2(x1))
        x1 = self.pool3(self.conv3(x1))
        x1 = x1.view(x1.size(0), -1)
        x1 = self.dropout(x1)
        
        x2 = self.pool1(self.conv1(x2))
        x2 = self.pool2(self.conv2(x2))
        x2 = self.pool3(self.conv3(x2))
        x2 = x2.view(x2.size(0), -1)
        x2 = self.dropout(x2)
        
        x = torch.abs(x1 - x2)
        x = self.fc1(x)
        
        return x'''



class SimpleConvNet(nn.Module):
    def __init__(self):
        super(SimpleConvNet, self).__init__()
        self.conv1 = nn.Conv2d(in_channels=1, out_channels=3, kernel_size=3)
        self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)
        self.pool2 = nn.MaxPool2d(kernel_size=2, stride=2)
        
        self.flattened_size = 3 * 12 * 12 # Adjusted for 50x50 input size reduced by two pooling layers
        self.fc1 = nn.Linear(self.flattened_size, 1)
        
        self.dropout = nn.Dropout(p=0.5)

    def forward(self, x1, x2):
        x1 = self.pool1(self.conv1(x1))
        x1 = self.pool2(x1)
        x1 = x1.view(x1.size(0), -1)
        x1 = self.dropout(x1)
        
        x2 = self.pool1(self.conv1(x2))
        x2 = self.pool2(x2)
        x2 = x2.view(x2.size(0), -1)
        x2 = self.dropout(x2)
        
        x = torch.abs(x1 - x2)
        x = self.fc1(x)
        
        return x
    
    

class BiggerConvNet(nn.Module):
    def __init__(self):
        super(BiggerConvNet, self).__init__()
        self.conv1 = nn.Conv2d(in_channels=1, out_channels=9, kernel_size=3)
        self.conv2 = nn.Conv2d(in_channels=9, out_channels=27, kernel_size=3)
        self.conv3 = nn.Conv2d(in_channels=27, out_channels=81, kernel_size=3)
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2)
        
        self.flattened_size = 81 * 4 * 4  # Adjusted for 50x50 input size reduced by three pooling layers
        self.fc1 = nn.Linear(self.flattened_size, 1)
        
        self.dropout = nn.Dropout(p=0.5)

    def forward(self, x1, x2):
        x1 = self.pool(self.conv1(x1))
        x1 = self.pool(self.conv2(x1))
        x1 = self.pool(self.conv3(x1))
        x1 = x1.view(x1.size(0), -1)
        x1 = self.dropout(x1)
        
        x2 = self.pool(self.conv1(x2))
        x2 = self.pool(self.conv2(x2))
        x2 = self.pool(self.conv3(x2))
        x2 = x2.view(x2.size(0), -1)
        x2 = self.dropout(x2)
        
        x = torch.abs(x1 - x2)
        x = self.fc1(x)
        
        return x
        
        
class ThirdFurtherAdjustedSiameseBambooNN(nn.Module):
    def __init__(self):
        super(ThirdFurtherAdjustedSiameseBambooNN, self).__init__()
        self.embedding_net = nn.Sequential(
            nn.Conv2d(1, 4, kernel_size=3),  # Reduce filters in the first Conv2d layer
            nn.BatchNorm2d(4),
            nn.ReLU(),
            nn.Conv2d(4, 4, kernel_size=3), 
            nn.BatchNorm2d(4),
            nn.ReLU(),
            nn.Conv2d(4, 4, kernel_size=3), 
            nn.BatchNorm2d(4),
            nn.ReLU(),
            nn.Flatten()
        )
        # Calculate the size of the fully connected layer input based on the spatial dimensions
        self.fc_input_size = self.get_fc_input_size((1, 112, 112))
        self.fc = nn.Sequential(
            nn.Linear(self.fc_input_size, 4),  # Reduce units in the first Linear layer
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(4, 2)  # Reduce units in the second Linear layer
        )
        self.out = nn.Linear(2, 1)  # Output 1 for similar, 0 for dissimilar

    def forward_one(self, x):
        x = x.view(-1, 1, 112, 112)  # Reshape input for convolutional layer
        return self.embedding_net(x)

    def forward(self, x1, x2):
        output1 = self.forward_one(x1)
        output2 = self.forward_one(x2)
        distance = torch.abs(output1 - output2)
        embedded = self.fc(distance)
        output = self.out(embedded)
        return output

    def get_fc_input_size(self, shape):
        with torch.no_grad():
            x = torch.zeros(1, *shape)
            x = self.embedding_net(x)
            return x.view(1, -1).size(1)        
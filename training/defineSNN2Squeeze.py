import torch
import torch.nn as nn
import torch.nn.functional as F
from torchvision import models

# Define the Siamese neural network
class SqueezeAdjusted(nn.Module):
    def __init__(self):
        super(SqueezeAdjusted, self).__init__()
        self.embedding_net = models.squeezenet1_1(pretrained=False) 
        
        # Freeze the weights
        for param in self.embedding_net.parameters():
            param.requires_grad = False
        
        self.embedding_net.classifier[1] = nn.Conv2d(512, 128, kernel_size=(1,1), stride=(1,1))  # Adjust the last layer to match your needs
        self.fc_input_size = self.get_fc_input_size((3, 224, 224))  # Adjust the input size to match SqueezeNet's input
        self.fc = nn.Sequential(
            nn.Linear(self.fc_input_size, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 32)
        )
        self.out = nn.Linear(32, 1)

    def forward_one(self, x):
        x = x.view(-1, 3, 224, 224)  # Reshape input for SqueezeNet
        return self.embedding_net(x)

    def forward(self, x1, x2):
        output1 = self.forward_one(x1)
        output2 = self.forward_one(x2)
        distance = torch.abs(output1 - output2)
        embedded = self.fc(distance) # embedded = self.fc(distance.view(distance.size(0), -1))
        output = self.out(embedded)
        return output

    def get_fc_input_size(self, shape):
        with torch.no_grad():
            x = torch.zeros(1, *shape)
            x = self.embedding_net(x)
            return x.view(1, -1).size(1)
'''
# TRUNCATED SQUEEZE 
class SqueezeAdjusted(nn.Module):
    def __init__(self):
        super(SqueezeAdjusted, self).__init__()
        self.embedding_net = models.squeezenet1_1(pretrained=False)
        
        # Freeze all the weights
        for param in self.embedding_net.parameters():
            param.requires_grad = False
        
        # Truncate the model to keep only low-level feature extraction layers
        self.low_level_extractor = nn.Sequential(
            self.embedding_net.features[0],  # Conv2d(3, 64, kernel_size=(3, 3), stride=(2, 2))
            self.embedding_net.features[1],  # ReLU(inplace=True)
            self.embedding_net.features[2],  # MaxPool2d(kernel_size=3, stride=2, padding=1)
            self.embedding_net.features[3],  # Fire module 1
            self.embedding_net.features[4],  # Fire module 2
            self.embedding_net.features[5],  # MaxPool2d(kernel_size=3, stride=2, padding=1)
        )
        
        # Add a dimensionality reduction layer
        self.dim_reduction = nn.Conv2d(128, 128, kernel_size=(1,1), stride=(1,1))
        
        self.fc_input_size = self.get_fc_input_size((3, 224, 224))  # Adjust the input size to match SqueezeNet's input
        
        self.fc = nn.Sequential(
            nn.Linear(self.fc_input_size, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 32)
        )
        
        self.out = nn.Linear(32, 1)

    def forward_one(self, x):
        x = x.view(-1, 3, 224, 224)  # Reshape input for SqueezeNet
        x = self.low_level_extractor(x)
        x = self.dim_reduction(x)
        x = x.view(x.size(0), -1)  # Flatten the tensor
        return x

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
            x = self.low_level_extractor(x)
            x = self.dim_reduction(x)
            return x.view(1, -1).size(1)
'''        
# def decroter(fun):
#     def wrap(*args, **kwargs):
#         num_list = [num for num in args]
#         function = kwargs["method"]
#         if function == "add":
#             ans = None
#             for num in num_list:
#                 ans = num + ans
#                 return ans
#         elif function == "mul":
#             ans = None
#             for num in num_list:
#                 ans = num * ans
#                 return ans
#         elif function == "sub":
#             ans = None
#             for num in num_list:
#                 ans = num - ans
#                 return ans
#
#         elif function == "div":
#             ans = None
#             for num in num_list:
#                 ans = num / ans
#                 return ans
#
#     return wrap
#
#
# @decroter
# def calcy(*args, **kwargs):
#
#
# say_hellow()




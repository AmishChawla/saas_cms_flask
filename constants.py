# BASE_URL = 'https://resume-parser-fastapi.onrender.com/api'

BASE_URL = 'http://127.0.0.1:8000/api'


ROOT_URL = 'http://127.0.0.1:8000'

# ROOT_URL = 'http://35.154.190.245:8000'

# BASE_URL = 'http://35.154.190.245:8000/api'

# BASE_URL = 'http://127.0.0.1:8000/api'


# BASE_URL = 'http://35.154.190.245:8000/api'

# BASE_URL = 'http://35.154.190.245:8000/api'


# <script src="../static/assets/vendors/js/vendor.bundle.base.js"></script>

# <script>
#         var userId = document.querySelector('.button2').getAttribute('data-user-id');
#     </script>
#     <script>
#         function applyFilters() {
#         // Get the selected filter values
#         var roleFilter = document.getElementById("roleRangeDropdown").value;
#         var dateFilter = document.getElementById("dateRangeDropdown").value;
#         var statusFilter = document.getElementById("statusRangeDropdown").value;
#         var searchFilter = document.getElementById("searchInput").value.trim();
#         // Redirect to the admin dashboard with filter parameters
#         var redirectUrl = "{{ url_for('admin_dashboard') }}?role_filter=" + roleFilter + "&date_filter=" + dateFilter + "&status_filter=" + statusFilter + "&search_filter=" + searchFilter;
#         redirectToPage(redirectUrl);
#         document.getElementById("searchInput").value = searchFilter;
#     }
#
#
    # function redirectToPage(pageUrl) {
    #     // You can customize this function to perform the redirection as needed
    #     console.log(pageUrl);
    #     window.location.href = pageUrl;
    # }
# </script>









#==================================JS FOR DATATABLE=============================================
# //$(document).ready(function() {
# //    var table = $('#userTable').DataTable({
#  //       initComplete: function () {
#  //           // Add custom filter for the "Creation Time" column
# //            this.api().columns(6).every(function () {
# //                var column = this;
# //                var select = $('<select><option value="">All</option><option value="last_week">Last week</option><option value="last_month">Last month</option><option value="last_year">Last year</option></select>')
# //                    .appendTo($('#createTimeRangeDropdown').empty())
#  //                   .on('change', function () {
#  //                       var val = $(this).val();
#  //                       if (val === "") {
#   //                          column.search('').draw();
#   //                      } else {
#  //                           // Calculate date ranges
#  //                           var currentDate = new Date();
#  //                           var startDate;
#  //                           switch (val) {
#   //                              case "last_week":
#    //                                 startDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate() - 7);
#    //                                 break;
#     //                            case "last_month":
#     //                                startDate = new Date(currentDate.getFullYear(), currentDate.getMonth() - 1, currentDate.getDate());
#    //                                 break;
#    //                             case "last_year":
#    //                                 startDate = new Date(currentDate.getFullYear() - 1, currentDate.getMonth(), currentDate.getDate());
#    //                                 break;
#     //                        }
#   //                          var formattedStartDate = formatDate(startDate);
#   //                          var formattedCurrentDate = formatDate(currentDate);
#    //                         column.search(formattedStartDate + ' TO ' + formattedCurrentDate, true, false).draw();
#    //                     }
#   //                  });
#   //          });
#   //      }
#   //  });
# //});
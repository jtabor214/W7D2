class UsersController < ApplicationController

    def index 
        @users = User.all
        render :index
    end

    def show 
        @user = User.find_by(params[:id])
        render :show
    end

    def new
        @user = User.new
        render :new
    end

    def create
        @user = User.new(user_params) 

        if @user.save
            #login(@user)
            redirect_to user_url(@user)
        else
            render json: @user.errors.full_messages, status: 422
        end
    end

    private 

    def user_params
        params.require(:user).permit(:username, :email, :password)
    end
end

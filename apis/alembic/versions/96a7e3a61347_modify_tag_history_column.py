"""modify_tag_history_column

Revision ID: 96a7e3a61347
Revises: 4ba9d4b98ea1
Create Date: 2021-10-06 11:55:30.187627

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '96a7e3a61347'
down_revision = '4ba9d4b98ea1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('issue_tag_history', sa.Column('historys', sa.ARRAY(postgresql.JSONB(astext_type=sa.Text())), nullable=True))
    op.drop_column('issue_tag_history', 'history')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('issue_tag_history', sa.Column('history', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True))
    op.drop_column('issue_tag_history', 'historys')
    # ### end Alembic commands ###